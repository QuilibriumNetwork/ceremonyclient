//! The node's current AutoNAT-confirmed external address, one per transport.
//!
//! AutoNAT v1 reports the address each dial-back server reached us at. The
//! swarm keeps every address it has ever confirmed, but PeerInfo must carry
//! the current one: after a dynamic-IP change the old address is useless to
//! the peers that dial it. [`ExternalAddrTracker`] keeps, per transport, the
//! latest confirmed address that is globally routable and on one of our listen
//! ports, but only while AutoNAT holds the node public. It drops every address
//! when AutoNAT finds the node private, and moves an established address to a
//! different IP only once two servers on distinct IPs confirm the new one, so
//! a single dishonest operator, however many nodes it runs behind one IP,
//! cannot redirect the peers that dial us.
//!
//! Addresses do not age out. The swarm's expiry signal is handled, but nothing
//! emits it today: AutoNAT v1 only confirms, and the node never calls
//! `remove_external_address`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::autonat::NatStatus;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tracing::{info, warn};

/// The transports the node listens on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternalTransport {
    Tcp,
    Quic,
}

impl ExternalTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalTransport::Tcp => "tcp",
            ExternalTransport::Quic => "quic",
        }
    }
}

/// The event behind the latest change of the confirmed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalAddrChange {
    /// An AutoNAT server dialed us back on an address we did not hold.
    Confirmed,
    /// The swarm expired a confirmed address (nothing emits this today).
    Expired,
    /// AutoNAT found the node unreachable and dropped every address.
    Private,
}

impl ExternalAddrChange {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalAddrChange::Confirmed => "confirmed",
            ExternalAddrChange::Expired => "expired",
            ExternalAddrChange::Private => "autonat_private",
        }
    }
}

/// The current confirmed external addresses, as published to the node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfirmedExternalAddrs {
    /// At most one address per transport, most recently accepted first,
    /// without a trailing `/p2p/...`.
    pub addrs: Vec<String>,
    /// What changed `addrs` last; `None` until the first change.
    pub last_change: Option<ExternalAddrChange>,
    /// AutoNAT's view behind `addrs`, for operator lines.
    pub autonat: AutonatSummary,
}

/// AutoNAT's view of this node's reachability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutonatSummary {
    /// `public`, `private` or `unknown`.
    pub nat_status: &'static str,
    /// The current run of probes without a dial-back; `None` while the
    /// latest probe brought one, or before any failed.
    pub probe_failure: Option<ProbeFailureSummary>,
}

impl Default for AutonatSummary {
    fn default() -> Self {
        Self { nat_status: "unknown", probe_failure: None }
    }
}

/// A run of AutoNAT probes without a dial-back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeFailureSummary {
    /// The run's most frequent failure class (`timeout`, `dial_error`, ...).
    pub class: &'static str,
    /// Probes in the run.
    pub probes: u32,
    /// When the run began.
    pub since: std::time::Instant,
    /// Servers on distinct IPs dialed this node back and reached none of
    /// its addresses (`dial_error`), or did not finish within AutoNAT's
    /// timeout (`timeout`, as when a NAT drops the dial-backs): the node is
    /// unreachable, as opposed to probes that fail for other reasons.
    pub unreachable: bool,
}

/// Transport and port of a TCP or QUIC multiaddr.
pub fn transport_and_port(addr: &Multiaddr) -> Option<(ExternalTransport, u16)> {
    let (mut tcp, mut udp, mut quic) = (None, None, false);
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(port) => tcp = Some(port),
            Protocol::Udp(port) => udp = Some(port),
            Protocol::QuicV1 | Protocol::Quic => quic = true,
            _ => {}
        }
    }
    if quic {
        udp.map(|port| (ExternalTransport::Quic, port))
    } else {
        tcp.map(|port| (ExternalTransport::Tcp, port))
    }
}

/// Transport of a multiaddr string, `None` when it is neither TCP nor QUIC.
pub fn transport_of(addr: &str) -> Option<ExternalTransport> {
    let addr: Multiaddr = addr.parse().ok()?;
    transport_and_port(&addr).map(|(transport, _)| transport)
}

fn without_peer_id(addr: &Multiaddr) -> Multiaddr {
    let mut addr = addr.clone();
    while matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    addr
}

/// What [`ExternalAddrTracker::on_confirmed`] did with an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    /// Not usable as our address: names no TCP/QUIC transport, a port we do
    /// not listen on, or an IP peers cannot route to.
    Rejected(&'static str),
    /// Already the current address of its transport.
    Unchanged,
    /// A different IP for a transport that has an address; it waits for a
    /// second server on another IP.
    Pending,
    /// The confirmed set changed.
    Accepted,
}

/// The AutoNAT server behind a dial-back: its peer and the remote IP of its
/// connection, when known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbeServer {
    pub(crate) peer: PeerId,
    pub(crate) ip: Option<IpAddr>,
}

impl ProbeServer {
    /// Distinct peers on distinct known IPs: one operator's nodes behind one
    /// IP (one IPv6 /64, see `autonat_servers::ip_group`) count once.
    fn independent_of(&self, other: &ProbeServer) -> bool {
        self.peer != other.peer && matches!((self.ip, other.ip), (Some(a), Some(b)) if a != b)
    }
}

/// How long a move to a new IP may wait for its second server before a
/// warning.
pub(crate) const PENDING_WARN_AFTER: Duration = Duration::from_secs(30 * 60);

/// A move of a transport's address to a new IP, waiting for a second server.
struct PendingMove {
    transport: ExternalTransport,
    addr: Multiaddr,
    server: ProbeServer,
    /// When [`ExternalAddrTracker::pending_notices`] first saw it.
    since: Option<Instant>,
    warned: bool,
}

/// An operator line about a pending move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PendingNotice {
    /// A server confirmed this node at a new IP.
    Started { transport: ExternalTransport },
    /// Still waiting after [`PENDING_WARN_AFTER`].
    Stale { transport: ExternalTransport, secs: u64 },
    /// The move ended: `moved`, `current_reconfirmed`, `replaced`,
    /// `expired` or `autonat_private`.
    Resolved { transport: ExternalTransport, secs: u64, outcome: &'static str },
}

/// Log a pending-move notice. These lines concern this node's own address.
pub(crate) fn log_pending(notice: &PendingNotice) {
    match notice {
        PendingNotice::Started { transport } => info!(
            transport = transport.as_str(),
            "AutoNAT confirmed this node at a new IP; PeerInfo keeps the current address until a \
             server on another IP confirms it"
        ),
        PendingNotice::Stale { transport, secs } => warn!(
            transport = transport.as_str(),
            pending_secs = secs,
            "a new IP of this node still awaits a second AutoNAT server on another IP, so PeerInfo \
             announces the old address; see the 'AutoNAT probes of this node' lines, and report \
             this line if probes succeed"
        ),
        PendingNotice::Resolved { transport, secs, outcome } => info!(
            transport = transport.as_str(),
            pending_secs = secs,
            outcome,
            "pending move of this node's address to a new IP ended"
        ),
    }
}

/// A signal from the swarm event loop to [`ExternalAddrTracker::apply`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExternalAddrEvent<'a> {
    /// An AutoNAT probe finished; `Some` when its server dialed us back on
    /// that address.
    Probe(Option<(&'a Multiaddr, ProbeServer)>),
    /// AutoNAT's status flipped.
    StatusChanged,
    /// The swarm expired one of its confirmed addresses.
    Expired(&'a Multiaddr),
}

/// What [`ExternalAddrTracker::apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// A dial-back from a server while AutoNAT holds the node public.
    Confirm(ConfirmOutcome),
    /// A dial-back while AutoNAT's status is still unknown.
    NotPublic,
    /// AutoNAT holds the node private: every address dropped (`true` when
    /// one was held).
    Private(bool),
    /// The swarm expired an address (`true` when it was ours).
    Expired(bool),
    /// Nothing to do.
    Nothing,
}

impl Applied {
    /// Whether the confirmed set changed. The swarm loop compares the
    /// published value instead, which also carries AutoNAT's view.
    #[cfg(test)]
    pub(crate) fn changed(self) -> bool {
        matches!(
            self,
            Applied::Confirm(ConfirmOutcome::Accepted) | Applied::Private(true) | Applied::Expired(true)
        )
    }
}

/// Tracks the current confirmed external address of each transport.
pub(crate) struct ExternalAddrTracker {
    tcp_port: Option<u16>,
    quic_port: Option<u16>,
    routable: fn(&Multiaddr) -> bool,
    /// Most recently accepted first; at most one per transport.
    current: Vec<(ExternalTransport, Multiaddr)>,
    /// A different address for a transport that has one, with the server
    /// that confirmed it; at most one per transport.
    pending: Vec<PendingMove>,
    /// Moves that ended since the last `pending_notices`, with their start.
    ended: Vec<(ExternalTransport, Option<Instant>, &'static str)>,
    last_change: Option<ExternalAddrChange>,
}

impl ExternalAddrTracker {
    /// `tcp_port`/`quic_port` are the ports of our listeners; `routable`
    /// decides which IPs peers can reach.
    pub(crate) fn new(
        tcp_port: Option<u16>,
        quic_port: Option<u16>,
        routable: fn(&Multiaddr) -> bool,
    ) -> Self {
        Self {
            tcp_port,
            quic_port,
            routable,
            current: Vec::new(),
            pending: Vec::new(),
            ended: Vec::new(),
            last_change: None,
        }
    }

    /// Apply `event`, given AutoNAT's status after it.
    ///
    /// A dial-back counts only while the status is public. AutoNAT keeps a
    /// private status through a public reply while it still has confidence
    /// in it (it only lowers that confidence) yet reports the reply anyway;
    /// accepting it would announce an address AutoNAT holds unreachable, and
    /// later private replies, which only raise the confidence again, would
    /// never clear it. So every probe outcome that leaves the status private
    /// drops all addresses. The status already reflects the probe when its
    /// event reaches the swarm: the behaviour updates it while handling the
    /// response and drains its queued events before handling the next one.
    pub(crate) fn apply(&mut self, event: ExternalAddrEvent<'_>, nat: &NatStatus) -> Applied {
        match event {
            ExternalAddrEvent::Expired(addr) => Applied::Expired(self.on_expired(addr)),
            ExternalAddrEvent::Probe(_) | ExternalAddrEvent::StatusChanged
                if *nat == NatStatus::Private =>
            {
                Applied::Private(self.on_private())
            }
            ExternalAddrEvent::Probe(Some((addr, server))) if nat.is_public() => {
                Applied::Confirm(self.on_confirmed(addr, server))
            }
            ExternalAddrEvent::Probe(Some(_)) => Applied::NotPublic,
            ExternalAddrEvent::Probe(None) | ExternalAddrEvent::StatusChanged => Applied::Nothing,
        }
    }

    /// `server` dialed us back on `address`.
    fn on_confirmed(&mut self, address: &Multiaddr, server: ProbeServer) -> ConfirmOutcome {
        let addr = without_peer_id(address);
        let Some((transport, port)) = transport_and_port(&addr) else {
            return ConfirmOutcome::Rejected("transport");
        };
        let listen_port = match transport {
            ExternalTransport::Tcp => self.tcp_port,
            ExternalTransport::Quic => self.quic_port,
        };
        if listen_port != Some(port) {
            return ConfirmOutcome::Rejected("port");
        }
        if !(self.routable)(&addr) {
            return ConfirmOutcome::Rejected("not_routable");
        }
        let pending = self.pending.iter().position(|p| p.transport == transport);
        let new_move = |addr| PendingMove { transport, addr, server, since: None, warned: false };
        match self.current.iter().position(|(t, _)| *t == transport) {
            Some(i) if self.current[i].1 == addr => {
                // A server still sees us here, so a different pending IP
                // was not where peers reach us.
                if let Some(j) = pending {
                    self.end_pending(j, "current_reconfirmed");
                }
                ConfirmOutcome::Unchanged
            }
            Some(i) => match pending {
                Some(j) if self.pending[j].addr == addr && self.pending[j].server.independent_of(&server) => {
                    self.end_pending(j, "moved");
                    self.current.remove(i);
                    self.current.insert(0, (transport, addr));
                    self.last_change = Some(ExternalAddrChange::Confirmed);
                    ConfirmOutcome::Accepted
                }
                Some(j) if self.pending[j].addr == addr => {
                    // A first server of unknown IP can never be told apart
                    // from a second one; keep one whose IP is known.
                    if self.pending[j].server.ip.is_none() {
                        self.pending[j].server = server;
                    }
                    ConfirmOutcome::Pending
                }
                Some(j) => {
                    self.end_pending(j, "replaced");
                    self.pending.push(new_move(addr));
                    ConfirmOutcome::Pending
                }
                None => {
                    self.pending.push(new_move(addr));
                    ConfirmOutcome::Pending
                }
            },
            None => {
                if let Some(j) = pending {
                    self.end_pending(j, "moved");
                }
                self.current.insert(0, (transport, addr));
                self.last_change = Some(ExternalAddrChange::Confirmed);
                ConfirmOutcome::Accepted
            }
        }
    }

    /// The swarm expired `address`. Returns whether the confirmed set changed.
    fn on_expired(&mut self, address: &Multiaddr) -> bool {
        let addr = without_peer_id(address);
        while let Some(j) = self.pending.iter().position(|p| p.addr == addr) {
            self.end_pending(j, "expired");
        }
        let Some(i) = self.current.iter().position(|(_, a)| *a == addr) else {
            return false;
        };
        self.current.remove(i);
        self.last_change = Some(ExternalAddrChange::Expired);
        true
    }

    /// AutoNAT found the node private. Returns whether the confirmed set
    /// changed.
    fn on_private(&mut self) -> bool {
        while !self.pending.is_empty() {
            self.end_pending(0, "autonat_private");
        }
        if self.current.is_empty() {
            return false;
        }
        self.current.clear();
        self.last_change = Some(ExternalAddrChange::Private);
        true
    }

    fn end_pending(&mut self, j: usize, outcome: &'static str) {
        let ended = self.pending.remove(j);
        self.ended.push((ended.transport, ended.since, outcome));
    }

    /// Lines about moves to a new IP, as of `now`: one when a move starts,
    /// a warning once it has waited [`PENDING_WARN_AFTER`], one with its age
    /// when it ends. The swarm loop calls this after every change.
    pub(crate) fn pending_notices(&mut self, now: Instant) -> Vec<PendingNotice> {
        let age = |since: Instant| now.saturating_duration_since(since).as_secs();
        let mut notices: Vec<PendingNotice> = self
            .ended
            .drain(..)
            .filter_map(|(transport, since, outcome)| {
                since.map(|since| PendingNotice::Resolved { transport, secs: age(since), outcome })
            })
            .collect();
        for p in &mut self.pending {
            match p.since {
                None => {
                    p.since = Some(now);
                    notices.push(PendingNotice::Started { transport: p.transport });
                }
                Some(since) if !p.warned && now.saturating_duration_since(since) >= PENDING_WARN_AFTER => {
                    p.warned = true;
                    notices.push(PendingNotice::Stale { transport: p.transport, secs: age(since) });
                }
                _ => {}
            }
        }
        notices
    }

    pub(crate) fn snapshot(&self) -> ConfirmedExternalAddrs {
        ConfirmedExternalAddrs {
            addrs: self.current.iter().map(|(_, a)| a.to_string()).collect(),
            last_change: self.last_change,
            autonat: AutonatSummary::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node's routability rule, widened to the documentation ranges the
    /// tests use in place of real public addresses.
    fn routable(addr: &Multiaddr) -> bool {
        let documentation = addr.iter().any(|p| match p {
            Protocol::Ip4(ip) => ip.is_documentation(),
            _ => false,
        });
        documentation || crate::node::is_routable(addr)
    }

    fn tracker() -> ExternalAddrTracker {
        ExternalAddrTracker::new(Some(8336), Some(8336), routable)
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn with_peer(s: &str, server: PeerId) -> Multiaddr {
        ma(s).with(Protocol::P2p(server))
    }

    fn addrs(t: &ExternalAddrTracker) -> Vec<String> {
        t.snapshot().addrs
    }

    /// A server on an IP that no other test server has.
    fn any_server() -> ProbeServer {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n);
        ProbeServer { peer: PeerId::random(), ip: Some(IpAddr::V6(ip)) }
    }

    fn server_on(ip: &str) -> ProbeServer {
        ProbeServer { peer: PeerId::random(), ip: Some(ip.parse().unwrap()) }
    }

    #[test]
    fn first_confirmation_is_accepted_without_its_peer_id() {
        let mut t = tracker();
        let server = any_server();
        let me = PeerId::random();
        assert_eq!(
            t.on_confirmed(&with_peer("/ip4/203.0.113.7/tcp/8336", me), server),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(t.snapshot().last_change, Some(ExternalAddrChange::Confirmed));
    }

    #[test]
    fn reconfirming_the_current_address_changes_nothing() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let before = t.snapshot();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server()),
            ConfirmOutcome::Unchanged
        );
        assert_eq!(t.snapshot(), before);
    }

    /// A dynamic-IP change: the new address replaces the old once two
    /// distinct servers confirm it, and the old one is gone.
    #[test]
    fn a_new_ip_replaces_the_old_after_two_distinct_servers() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let first = any_server();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), first),
            ConfirmOutcome::Pending
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        // The same server again does not count twice.
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), first),
            ConfirmOutcome::Pending
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server()),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/198.51.100.9/tcp/8336"]);
    }

    /// Nodes behind one IP are one operator: however many confirm a new IP,
    /// it waits for a server on another IP.
    #[test]
    fn servers_sharing_an_ip_count_once() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        for _ in 0..5 {
            assert_eq!(
                t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server_on("192.0.2.44")),
                ConfirmOutcome::Pending
            );
        }
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server_on("192.0.2.45")),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/198.51.100.9/tcp/8336"]);
    }

    /// A move to a new IP logs once when it starts, warns once after 30
    /// minutes, and logs its age when it ends.
    #[test]
    fn a_pending_move_is_reported_warned_once_and_ended_with_its_age() {
        use PendingNotice::*;
        let t0 = Instant::now();
        let at = |m: u64| t0 + Duration::from_secs(60 * m);
        let mut t = tracker();
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert!(t.pending_notices(at(0)).is_empty());
        t.on_confirmed(&b, server_on("192.0.2.44"));
        assert_eq!(t.pending_notices(at(0)), vec![Started { transport: ExternalTransport::Tcp }]);
        t.on_confirmed(&b, server_on("192.0.2.44"));
        assert!(t.pending_notices(at(10)).is_empty());
        assert_eq!(
            t.pending_notices(at(31)),
            vec![Stale { transport: ExternalTransport::Tcp, secs: 31 * 60 }]
        );
        assert!(t.pending_notices(at(40)).is_empty());
        assert_eq!(t.on_confirmed(&b, server_on("192.0.2.45")), ConfirmOutcome::Accepted);
        assert_eq!(
            t.pending_notices(at(45)),
            vec![Resolved { transport: ExternalTransport::Tcp, secs: 45 * 60, outcome: "moved" }]
        );
        assert!(t.pending_notices(at(50)).is_empty());
    }

    /// A server of unknown IP never counts as the second one, and gives its
    /// pending slot to a server whose IP is known.
    #[test]
    fn a_server_of_unknown_ip_does_not_count_twice() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let unknown = || ProbeServer { peer: PeerId::random(), ip: None };
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(t.on_confirmed(&b, server_on("192.0.2.44")), ConfirmOutcome::Pending);
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(t.on_confirmed(&b, server_on("192.0.2.45")), ConfirmOutcome::Accepted);
    }

    /// One server's claim is dropped once another server still reaches us
    /// on the current address.
    #[test]
    fn a_current_reconfirmation_discards_a_pending_ip() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server());
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server()),
            ConfirmOutcome::Pending
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
    }

    #[test]
    fn transports_are_tracked_separately_newest_first() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336/quic-v1"), any_server());
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert_eq!(
            addrs(&t),
            vec!["/ip4/203.0.113.7/tcp/8336", "/ip4/203.0.113.7/udp/8336/quic-v1"]
        );
        // Replacing the QUIC address moves it to the front and keeps TCP.
        t.on_confirmed(&ma("/ip4/198.51.100.9/udp/8336/quic-v1"), any_server());
        t.on_confirmed(&ma("/ip4/198.51.100.9/udp/8336/quic-v1"), any_server());
        assert_eq!(
            addrs(&t),
            vec!["/ip4/198.51.100.9/udp/8336/quic-v1", "/ip4/203.0.113.7/tcp/8336"]
        );
    }

    #[test]
    fn expiry_removes_the_address_and_reports_it() {
        let mut t = tracker();
        let server = any_server();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert!(!t.on_expired(&ma("/ip4/198.51.100.9/tcp/8336")));
        assert!(t.on_expired(&with_peer("/ip4/203.0.113.7/tcp/8336", server.peer)));
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, Some(ExternalAddrChange::Expired));
        // With nothing established, the next confirmation needs one server.
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server),
            ConfirmOutcome::Accepted
        );
    }

    #[test]
    fn private_status_clears_every_address() {
        let mut t = tracker();
        assert!(!t.on_private());
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336/quic-v1"), any_server());
        assert!(t.on_private());
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, Some(ExternalAddrChange::Private));
    }

    #[test]
    fn rejects_other_ports_and_transports() {
        let mut t = ExternalAddrTracker::new(Some(8336), None, routable);
        let server = any_server();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/40123"), server),
            ConfirmOutcome::Rejected("port")
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336/quic-v1"), server),
            ConfirmOutcome::Rejected("port")
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336"), server),
            ConfirmOutcome::Rejected("transport")
        );
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn rejects_addresses_peers_cannot_route_to() {
        let mut t = tracker();
        for addr in [
            "/ip4/0.0.0.0/tcp/8336",
            "/ip4/127.0.0.1/tcp/8336",
            "/ip4/10.1.2.3/tcp/8336",
            "/ip4/192.168.1.20/udp/8336/quic-v1",
        ] {
            assert_eq!(
                t.on_confirmed(&ma(addr), any_server()),
                ConfirmOutcome::Rejected("not_routable"),
                "{addr}"
            );
        }
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, None);
    }

    fn public() -> NatStatus {
        NatStatus::Public(ma("/ip4/203.0.113.7/tcp/8336"))
    }

    /// AutoNAT reports a public reply while it still holds the node private:
    /// the address must not be announced, and a private outcome drops what
    /// was held.
    #[test]
    fn a_dial_back_while_autonat_holds_the_node_private_is_not_announced() {
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        assert_eq!(
            t.apply(ExternalAddrEvent::Probe(Some((&a, any_server()))), &public()),
            Applied::Confirm(ConfirmOutcome::Accepted)
        );
        // A failed dial-back that leaves the status private clears it.
        let cleared = t.apply(ExternalAddrEvent::Probe(None), &NatStatus::Private);
        assert_eq!(cleared, Applied::Private(true));
        assert!(cleared.changed());
        assert!(addrs(&t).is_empty());
        // A public reply that only lowers AutoNAT's confidence in private.
        let reply = t.apply(ExternalAddrEvent::Probe(Some((&a, any_server()))), &NatStatus::Private);
        assert_eq!(reply, Applied::Private(false));
        assert!(!reply.changed());
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn a_dial_back_before_autonat_has_a_status_is_ignored() {
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        assert_eq!(
            t.apply(ExternalAddrEvent::Probe(Some((&a, any_server()))), &NatStatus::Unknown),
            Applied::NotPublic
        );
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn a_flip_to_private_clears_every_address() {
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        t.apply(ExternalAddrEvent::Probe(Some((&a, any_server()))), &public());
        assert_eq!(t.apply(ExternalAddrEvent::StatusChanged, &public()), Applied::Nothing);
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(
            t.apply(ExternalAddrEvent::StatusChanged, &NatStatus::Private),
            Applied::Private(true)
        );
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn private_and_expiry_clear_pending_entries() {
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        t.apply(ExternalAddrEvent::Probe(Some((&a, any_server()))), &public());
        let first = t.apply(ExternalAddrEvent::Probe(Some((&b, any_server()))), &public());
        assert_eq!(first, Applied::Confirm(ConfirmOutcome::Pending));
        assert!(!first.changed());
        assert_eq!(t.pending.len(), 1);
        // Expiry of the pending address drops it; A stays.
        assert_eq!(t.apply(ExternalAddrEvent::Expired(&b), &public()), Applied::Expired(false));
        assert!(t.pending.is_empty());
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        // So B needs two fresh servers again.
        assert_eq!(
            t.apply(ExternalAddrEvent::Probe(Some((&b, any_server()))), &public()),
            Applied::Confirm(ConfirmOutcome::Pending)
        );
        assert_eq!(
            t.apply(ExternalAddrEvent::StatusChanged, &NatStatus::Private),
            Applied::Private(true)
        );
        assert!(t.pending.is_empty());
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn transport_of_reads_tcp_and_quic() {
        assert_eq!(transport_of("/ip4/0.0.0.0/tcp/8336"), Some(ExternalTransport::Tcp));
        assert_eq!(
            transport_of("/ip4/0.0.0.0/udp/8336/quic-v1"),
            Some(ExternalTransport::Quic)
        );
        assert_eq!(transport_of("/ip4/0.0.0.0/udp/8336"), None);
        assert_eq!(transport_of("not a multiaddr"), None);
    }
}
