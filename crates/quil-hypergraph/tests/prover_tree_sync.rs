//! CRDT-level prover-tree sync round-trip: a stale/empty "follower" CRDT syncs
//! the global prover shard from a "leader" CRDT and its prover root converges to
//! the leader's. This is the invariant behind the archive "prover root MISMATCH"
//! reports — a follower that syncs correctly MUST reach the source root — and it
//! had no end-to-end coverage (only the forest primitive `diff_leaves` was
//! tested, not `sync_shard_phase_from` + `compute_shard_root` together).
//!
//! The sync runs fully in-process: an [`InProcTreeReader`] calls the source
//! CRDT's `serve_forest_node` / `serve_forest_value` (the same server methods
//! the gRPC `RemoteTreeReader` wraps), so no network is involved.

use std::sync::Arc;

use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{KeyHash, OwnedValue, Version};

use quil_hypergraph::testing::{MemStore, StubProver};
use quil_hypergraph::{HypergraphCrdt, Location};

/// The global intrinsic (prover) shard. `compute_shard_root` uses only `l2`;
/// the forest tree-id / sync `shard_id` for this single-shard app is `l2`.
const GLOBAL_APP: [u8; 32] = [0xffu8; 32];

fn global_prover_shard() -> quil_types::store::ShardKey {
    quil_types::store::ShardKey { l1: [0u8; 3], l2: GLOBAL_APP }
}

fn fresh_crdt() -> Arc<HypergraphCrdt> {
    Arc::new(HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(StubProver)))
}

/// A [`TreeReader`] over a source CRDT's forest, calling its `serve_forest_*`
/// methods directly (no gRPC). Mirrors `quil_rpc::RemoteTreeReader`.
struct InProcTreeReader {
    source: Arc<HypergraphCrdt>,
    shard_id: Vec<u8>,
    phase: usize,
}

impl TreeReader for InProcTreeReader {
    fn get_node_option(&self, node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
        let key_bytes = borsh::to_vec(node_key)?;
        match self.source.serve_forest_node(&self.shard_id, self.phase, &key_bytes) {
            Some(b) => Ok(Some(borsh::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> anyhow::Result<Option<OwnedValue>> {
        Ok(self
            .source
            .serve_forest_value(&self.shard_id, self.phase, max_version, key_hash.0))
    }

    fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
        // Merkle-diff sync never calls this (it addresses nodes explicitly).
        Ok(None)
    }
}

/// Seed `n` distinct prover-like vertices under the global app into `crdt` and
/// commit at `frame`.
fn seed_and_commit(crdt: &HypergraphCrdt, n: u8, frame: u64) {
    for i in 0..n {
        let mut data = [0u8; 32];
        data[0] = i;
        data[31] = i.wrapping_mul(11);
        crdt.add_vertex(
            &Location { app_address: GLOBAL_APP, data_address: data },
            &vec![i; 48 + i as usize],
        )
        .unwrap();
    }
    crdt.commit(frame).unwrap();
}

/// Sync phase 0 (vertex-adds) of the global shard from `source` into `target`
/// and return the target's new prover root. Mirrors `forest_sync::sync_one_phase`
/// minus the blob fetch (roots are what the mismatch check compares).
fn sync_prover_phase0(target: &HypergraphCrdt, source: Arc<HypergraphCrdt>) -> Vec<u8> {
    let shard_id = GLOBAL_APP.to_vec();
    let (source_version, _root) = source
        .serve_forest_head(&shard_id, 0)
        .expect("source has a committed vertex-adds head for the prover shard");
    let reader = InProcTreeReader { source, shard_id: shard_id.clone(), phase: 0 };
    let (root, _ver, _changed) = target
        .sync_shard_phase_from(&reader, source_version, &shard_id, 0)
        .expect("sync_shard_phase_from");
    let _ = root;
    target.compute_shard_root("vertex", "adds", &global_prover_shard())
}

/// A follower that starts EMPTY converges to the leader's prover root.
#[test]
fn empty_follower_converges_to_leader_prover_root() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 10, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_eq!(leader_root.len(), 32);
    assert!(leader_root.iter().any(|&b| b != 0));

    let follower = fresh_crdt();
    // Sanity: the follower's prover root differs before sync.
    let before = follower.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_ne!(before, leader_root, "empty follower must differ pre-sync");

    let after = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(
        after, leader_root,
        "after syncing the prover shard the follower root must equal the leader's"
    );
}

/// A failed blob transfer must not install a matching tree with unreadable
/// state. Once all blobs are available, tree and blob state become visible
/// together.
#[test]
fn prepared_sync_waits_for_blobs_before_installing_tree() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 1, 1);
    let follower = fresh_crdt();
    let shard_id = GLOBAL_APP.to_vec();
    let (source_version, leader_root) = leader
        .serve_forest_head(&shard_id, 0)
        .expect("leader phase head");
    let reader = InProcTreeReader {
        source: leader.clone(),
        shard_id: shard_id.clone(),
        phase: 0,
    };
    let prepared = follower
        .prepare_shard_phase_sync(&reader, source_version, &shard_id, 0)
        .expect("prepare sync");
    assert!(!prepared.is_empty());
    assert_ne!(
        follower.compute_shard_root("vertex", "adds", &global_prover_shard()),
        leader_root,
        "no tree is installed before the blob transfer succeeds",
    );

    let blobs = prepared
        .changed_leaves()
        .into_iter()
        .map(|(data, _)| {
            let mut id = GLOBAL_APP.to_vec();
            id.extend_from_slice(&data);
            let blob = leader
                .peek_synced_blob(&global_prover_shard(), 0, &id)
                .expect("leader blob");
            (id, blob)
        })
        .collect::<Vec<_>>();
    follower
        .apply_prepared_shard_phase_sync(
            prepared,
            Some(&global_prover_shard()),
            &blobs,
        )
        .expect("atomic tree-and-blob install");
    assert_eq!(
        follower.compute_shard_root("vertex", "adds", &global_prover_shard()),
        leader_root,
    );
}

/// The unified subtree path must have the same ordering guarantee as whole-tree
/// sync: a failed blob transfer cannot advance the subtree commitment.
#[test]
fn prepared_subtree_sync_waits_for_blobs_before_installing_tree() {
    use quil_types::store::ShardKey;

    let app = *b"quil-app-address-0123456789abcd!";
    let shard = ShardKey { l1: [0u8; 3], l2: app };
    let vertex = Location { app_address: app, data_address: [0x00u8; 32] };
    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1);
    leader.set_unified_tree(true);
    leader.add_vertex(&vertex, b"subtree-data").unwrap();
    leader.commit(1).unwrap();
    let leader_root = leader.compute_shard_root("vertex", "adds", &shard);
    let pinned = <[u8; 32]>::try_from(leader_root.as_slice()).unwrap();

    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bit_path = follower.canonical_bits_for_prefix(&app, &[0u32]);
    let shard_id = app.to_vec();
    let (source_version, _) = leader
        .serve_forest_head(&shard_id, 0)
        .expect("leader phase head");
    let reader = InProcTreeReader { source: leader.clone(), shard_id, phase: 0 };
    let prepared = follower
        .prepare_shard_subtree_phase_sync(
            &reader,
            source_version,
            &app,
            0,
            &bit_path,
            Some(pinned),
        )
        .expect("prepare subtree sync");
    assert!(!prepared.is_empty());
    assert!(
        !follower.lookup_vertex(&vertex),
        "tree and blob state stay absent until blob transfer succeeds",
    );

    let blobs = prepared
        .changed_leaves()
        .into_iter()
        .map(|(data, _)| {
            let mut id = app.to_vec();
            id.extend_from_slice(&data);
            let blob = leader.peek_synced_blob(&shard, 0, &id).expect("leader blob");
            (id, blob)
        })
        .collect::<Vec<_>>();
    let (subtree_root, _) = follower
        .apply_prepared_shard_subtree_phase_sync(prepared, Some(&shard), &blobs)
        .expect("atomic subtree tree-and-blob install");
    assert!(follower.lookup_vertex(&vertex), "blob is readable after install");
    assert_eq!(
        subtree_root,
        leader.sub_shard_commitment("vertex", "adds", &shard, &[0u32]).as_slice(),
    );
}

/// A follower that is STALE (holds an older subset) converges after sync — the
/// Merkle diff carries only the missing/changed leaves and reaches the leader root.
#[test]
fn stale_follower_converges_to_leader_prover_root() {
    // Follower first: 4 vertices committed.
    let follower = fresh_crdt();
    seed_and_commit(&follower, 4, 1);
    let stale_root = follower.compute_shard_root("vertex", "adds", &global_prover_shard());

    // Leader: the same 4 PLUS 6 more (superset), committed.
    let leader = fresh_crdt();
    seed_and_commit(&leader, 10, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_ne!(stale_root, leader_root, "stale subset must differ from the leader");

    let after = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(after, leader_root, "stale follower converges to the leader prover root");
}

/// Phase-2 unified: a follower syncs a SPLIT app committed in UNIFIED mode as
/// ONE tree (shard_id = app `l2`, not 64 sub-shard trees) and converges to the
/// leader's app-phase root — the single-tree sync path the dispatch now routes
/// unified apps to (`prover_tree_syncer_prod::sync_shard_tree`).
#[test]
fn unified_split_app_follower_converges_via_single_tree_sync() {
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = quil_types::store::ShardKey { l1: [0u8; 3], l2: app };

    // Seed a 64-way split app in UNIFIED mode: all vertices land in ONE tree
    // keyed by the app address, spread (by top-6-bits) across logical sub-shards.
    let seed = |crdt: &HypergraphCrdt, n: u8| {
        crdt.set_shard_partition(app, 1); // 64-way
        crdt.set_unified_tree(true);
        for i in 0..n {
            let mut data = [0u8; 32];
            data[0] = i.wrapping_mul(4); // top-6-bits vary → different logical shards
            data[31] = i;
            crdt.add_vertex(
                &Location { app_address: app, data_address: data },
                &vec![i; 40 + i as usize],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
    };

    let leader = fresh_crdt();
    seed(&leader, 12);
    let leader_root = leader.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(leader_root.len(), 32);
    assert!(leader_root.iter().any(|&b| b != 0));

    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let before = follower.compute_shard_root("vertex", "adds", &sk);
    assert_ne!(before, leader_root, "empty unified follower differs pre-sync");

    // Sync the ONE app tree (shard_id = app l2), phase 0 — no per-sub-shard heads.
    let shard_id = app.to_vec();
    let (v_s, _r) = leader
        .serve_forest_head(&shard_id, 0)
        .expect("leader has a committed app-tree head");
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_phase_from(&reader, v_s, &shard_id, 0)
        .expect("sync_shard_phase_from");
    let after = follower.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(
        after, leader_root,
        "unified split-app follower converges to the leader app root via single-tree sync"
    );
}

/// Phase-2 shard-prover SUBTREE-RANGE sync: a follower covering ONLY shard X
/// pulls just X's subtree from the leader's app tree — NOT shards Y or the far
/// shard — authenticated against the leader's app root, and its local shard
/// commitment matches the leader's. This is what lets a shard prover store only
/// its shard yet stay consensus-consistent.
#[test]
fn shard_prover_pulls_only_its_subtree() {
    use quil_types::store::ShardKey;

    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    // Vertices in shard X (prefix [0], top-6-bits 0), shard Y (prefix [1]), + far.
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };
    let vfar = Location { app_address: app, data_address: [0x80u8; 32] };

    // LEADER: full unified app tree.
    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1);
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.add_vertex(&vfar, b"far-data").unwrap();
    leader.commit(1).unwrap();
    let leader_app_root = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(leader_app_root.len(), 32);
    let pinned = <[u8; 32]>::try_from(leader_app_root.as_slice()).unwrap();

    // FOLLOWER covering shard X only: EMPTY unified app tree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);

    // Sync ONLY shard X's subtree (phase 0), pinned to the leader's app root.
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).expect("leader app-tree head");
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    let (subtree_root, _ver, changed) = follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .expect("subtree sync");

    // Subtree-scoping: ONLY shard X's leaves transferred (byte0 in 0x00..0x03) —
    // no shard Y (0x04..) and no far shard (0x80). (Blobs are fetched separately
    // via `fetch_changed_blobs` in the wired path; here we assert on the forest.)
    assert!(!changed.is_empty(), "shard X leaves transferred");
    for (k, _) in &changed {
        assert!(k[0] < 0x04, "only shard X leaves transfer, got byte0 {:#x}", k[0]);
    }

    // The follower's local shard-X commitment equals the leader's (composes to
    // the app root) and equals the authenticated subtree root returned by sync.
    let follower_x_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(follower_x_commit, leader_x_commit, "shard X commitment matches leader");
    assert_eq!(follower_x_commit.as_slice(), subtree_root.as_slice(), "== authenticated subtree root");

    // Shard Y was NOT pulled → the follower's Y subtree is still empty, while the
    // leader's is populated. Concretely proves the sync did not fetch the whole app.
    let follower_y_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[1u32]);
    let leader_y_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[1u32]);
    assert_eq!(follower_y_commit, vec![0u8; 32], "follower shard Y stays empty (not pulled)");
    assert_ne!(leader_y_commit, vec![0u8; 32], "leader shard Y is populated");
}

/// SPIKE (unified-cutover worker design): a worker holding ONLY its covered
/// subtree reproduces the correct SUBTREE commitment, but NOT the whole-app
/// AGGREGATE root — the un-held sibling subtrees read as empty. Crux finding:
/// `app_engine` publishes the per-shard `state_root` as `compute_shard_root(app)`
/// (the whole-app aggregate over ALL sub-shards), which a subtree-only worker
/// canNOT reproduce. So the sharded unified design requires the per-shard
/// `state_root` to become the SUBTREE root (`sub_shard_commitment` /
/// `app_subtree_root(bit_path)`), bound to the app root via the co-path — not
/// the aggregate. Wiring the unified flip into workers is necessary but NOT
/// sufficient without this state_root semantic change.
#[test]
fn partial_worker_reproduces_subtree_root_but_not_app_aggregate() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };

    // Leader: full unified app tree, data in shard X ([0]) and Y ([1]).
    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1);
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.commit(1).unwrap();
    let leader_app_root = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    let pinned = <[u8; 32]>::try_from(leader_app_root.as_slice()).unwrap();

    // Follower covers shard X only; sync ONLY X's subtree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).unwrap();
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .unwrap();

    // (1) The SUBTREE commitment reproduces exactly on partial storage.
    let follower_x_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(
        follower_x_commit, leader_x_commit,
        "subtree root reproduces on partial storage"
    );

    // (2) The WHOLE-APP AGGREGATE does NOT — shard Y is un-held (empty) here.
    let follower_app_root = follower.compute_shard_root("vertex", "adds", &sk);
    assert_ne!(
        follower_app_root, leader_app_root,
        "partial worker CANNOT reproduce compute_shard_root(app) — the per-shard \
         state_root must be the SUBTREE root, not the whole-app aggregate"
    );
}

/// (A) producer/verifier symmetry: a subtree-only worker reproduces the exact
/// per-shard `state_root` (`sub_shard_commitment_for_filter`) that a full-holder
/// leader commits — from PARTIAL storage — and it differs from the whole-app
/// aggregate. This is what makes the sharded `state_root` (A) sound.
#[test]
fn sub_shard_commitment_for_filter_matches_leader_from_partial_storage() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };

    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1); // 64-way; shard X = prefix [0]
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.commit(1).unwrap();

    // Wire filter for shard X (prefix [0]) = app ‖ 0x00 (byte-suffix encoding).
    let filter_x = {
        let mut f = app.to_vec();
        f.push(0x00);
        f
    };
    let leader_app = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x = leader.sub_shard_commitment_for_filter("vertex", "adds", &filter_x);
    assert_eq!(leader_x.len(), 32);
    assert_ne!(
        leader_x, leader_app,
        "per-shard state_root (subtree) differs from the whole-app aggregate on a split app"
    );

    // Follower covers X only; sync just X's subtree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).unwrap();
    let pinned = <[u8; 32]>::try_from(leader_app.as_slice()).unwrap();
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .unwrap();

    // The subtree-only follower computes the SAME per-shard state_root.
    let follower_x = follower.sub_shard_commitment_for_filter("vertex", "adds", &filter_x);
    assert_eq!(
        follower_x, leader_x,
        "subtree-only worker reproduces the leader's per-shard state_root from partial storage"
    );
}

/// (A) unsplit app is a no-op: the bare-app filter's subtree root IS the app
/// root, so switching producer/verifier to `sub_shard_commitment_for_filter`
/// changes nothing for an unsplit app (or any app before its first split).
#[test]
fn sub_shard_commitment_for_filter_unsplit_app_is_app_root() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let crdt = fresh_crdt();
    crdt.set_unified_tree(true); // single-shard (no partition) → empty prefix
    let v = Location { app_address: app, data_address: [0x11u8; 32] };
    crdt.add_vertex(&v, b"data").unwrap();
    crdt.commit(1).unwrap();

    let filter_bare = app.to_vec(); // unsplit: bare 32-byte app filter
    let sub = crdt.sub_shard_commitment_for_filter("vertex", "adds", &filter_bare);
    let agg = crdt.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(sub, agg, "unsplit app: subtree root == whole-app aggregate (no-op)");
    assert_eq!(sub.len(), 32);
}

/// Re-syncing an already-converged follower is a no-op: the root is unchanged
/// (the diff is empty). Guards against a re-sync perturbing an in-sync node —
/// which would manifest as a node that oscillates in/out of "mismatch".
#[test]
fn resync_when_already_converged_is_stable() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 8, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());

    let follower = fresh_crdt();
    let first = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(first, leader_root, "first sync converges");

    let second = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(second, leader_root, "re-sync of a converged follower leaves the root unchanged");
}

// ---------------------------------------------------------------------------
// Leaf-blob gap: audit + repair
// ---------------------------------------------------------------------------

/// The `Location` `seed_and_commit` writes for index `i`.
fn seeded_location(i: u8) -> Location {
    let mut data = [0u8; 32];
    data[0] = i;
    data[31] = i.wrapping_mul(11);
    Location { app_address: GLOBAL_APP, data_address: data }
}

/// Pull `missing`'s blobs from `source` the way `forest_sync::repair_missing_blobs`
/// does, asserting each one binds to the leaf value the follower committed.
fn fetch_repair_blobs(
    source: &HypergraphCrdt,
    missing: &[([u8; 32], Vec<u8>)],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    missing
        .iter()
        .map(|(key_hash, leaf_value)| {
            let mut id = GLOBAL_APP.to_vec();
            id.extend_from_slice(key_hash);
            let blob = source
                .peek_synced_blob(&global_prover_shard(), 0, &id)
                .expect("source serves the blob for a leaf it committed");
            assert_eq!(
                &quil_tries::vertex_leaf_value(&blob).unwrap(),
                leaf_value,
                "a repair blob must hash to the locally committed commitment‖size",
            );
            (id, blob)
        })
        .collect()
}

/// THE REGRESSION. A tree-only install — the pre-atomic sync path, which
/// committed the commitment first and fetched blobs afterwards, so any error in
/// the fetch loop left a complete tree with no data behind it — produces a node
/// whose root is byte-identical to the leader's while every vertex is
/// unreadable. That state is self-perpetuating: the root check short-circuits
/// every later sync, the diff transfers nothing, and the hole is permanent.
///
/// The audit must find it from local state alone, and the repair must close it
/// without touching the tree.
#[test]
fn tree_only_install_leaves_a_blob_gap_the_audit_finds_and_repair_closes() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 6, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());
    let shard_id = GLOBAL_APP.to_vec();

    let follower = fresh_crdt();
    let after = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(after, leader_root, "the tree-only install still reaches the leader root");

    // Invisible to every root-level check — which is exactly why sync can never
    // notice it: a re-diff against the leader now transfers nothing.
    for i in 0..6u8 {
        assert!(
            !follower.lookup_vertex(&seeded_location(i)),
            "vertex {i} has a committed leaf but no readable data",
        );
    }

    let missing = follower.missing_vertex_blobs(&shard_id, 0).expect("audit");
    assert_eq!(missing.len(), 6, "the audit finds every leaf whose blob was never stored");
    assert!(
        follower.blob_audit_pending(&shard_id, 0),
        "an unrepaired tree stays pending so the next sync retries",
    );

    let blobs = fetch_repair_blobs(&leader, &missing);
    follower.install_vertex_blobs(&shard_id, 0, &blobs).expect("repair install");

    assert!(
        follower.missing_vertex_blobs(&shard_id, 0).unwrap().is_empty(),
        "the audit is clean after repair",
    );
    for i in 0..6u8 {
        assert!(follower.lookup_vertex(&seeded_location(i)), "vertex {i} is readable after repair");
    }
    assert_eq!(
        follower.compute_shard_root("vertex", "adds", &global_prover_shard()),
        leader_root,
        "repair installs DATA only — the commitment must not move",
    );
}

/// A node that materialized its own state has no gaps, so the audit must not
/// manufacture work: a clean sweep is what lets the syncer mark the tree and
/// stop paying O(leaves) every tick.
#[test]
fn a_fully_materialized_shard_audits_clean() {
    let crdt = fresh_crdt();
    seed_and_commit(&crdt, 5, 1);
    let shard_id = GLOBAL_APP.to_vec();

    assert!(crdt.missing_vertex_blobs(&shard_id, 0).unwrap().is_empty());
    assert!(crdt.blob_audit_pending(&shard_id, 0), "pending until something marks it");
    crdt.mark_blob_audit_done(&shard_id, 0);
    assert!(!crdt.blob_audit_pending(&shard_id, 0), "a clean tree is swept once, not per tick");
    assert!(
        crdt.blob_audit_pending(&shard_id, 1),
        "the mark is per phase — clearing adds must not silence removes",
    );
    // A shard this node never committed has nothing to audit.
    assert!(crdt.missing_vertex_blobs(b"uncommitted-shard-id-0123456789a", 0).unwrap().is_empty());
}

/// Absence is not the only failure: a blob that does not hash to its committed
/// leaf reads as no data at all (a stale prior-version blob, or the EMPTY
/// placeholder a remove stages). The audit must report those too — checking only
/// for presence is the bug that let a stale blob survive a sync.
#[test]
fn audit_reports_a_stored_blob_that_does_not_match_its_commitment() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 3, 1);
    let shard_id = GLOBAL_APP.to_vec();
    let follower = fresh_crdt();
    sync_prover_phase0(&follower, leader.clone());

    let missing = follower.missing_vertex_blobs(&shard_id, 0).unwrap();
    assert_eq!(missing.len(), 3);
    let blobs = fetch_repair_blobs(&leader, &missing);

    // Repair two correctly; store vertex 0's blob under vertex 1's id (a
    // present-but-unbound blob) and an EMPTY blob for the third.
    let wrong = vec![
        (blobs[0].0.clone(), blobs[0].1.clone()),
        (blobs[1].0.clone(), blobs[0].1.clone()),
        (blobs[2].0.clone(), Vec::new()),
    ];
    follower.install_vertex_blobs(&shard_id, 0, &wrong).unwrap();

    let still_missing = follower.missing_vertex_blobs(&shard_id, 0).unwrap();
    let ids: Vec<[u8; 32]> = still_missing.iter().map(|(kh, _)| *kh).collect();
    assert_eq!(ids.len(), 2, "both the unbound and the empty blob are still gaps");
    assert!(ids.contains(&missing[1].0), "the unbound blob is a gap");
    assert!(ids.contains(&missing[2].0), "the empty placeholder is a gap");
    assert!(!ids.contains(&missing[0].0), "the correctly repaired vertex is not");

    // The correct blobs close it.
    follower.install_vertex_blobs(&shard_id, 0, &blobs).unwrap();
    assert!(follower.missing_vertex_blobs(&shard_id, 0).unwrap().is_empty());
}

/// A removes-phase tombstone commits a leaf whose blob is empty BY CONSTRUCTION
/// (`stage_sized_tombstone` keeps the removed vertex's size in the leaf but
/// stores no data). Auditing those as gaps would report every tombstone forever
/// and no peer could ever serve a fix, so the sweep would never mark the tree
/// clean — an unbounded per-tick cost. They must be skipped.
#[test]
fn tombstone_leaves_are_never_reported_as_gaps() {
    let crdt = fresh_crdt();
    seed_and_commit(&crdt, 4, 1);
    crdt.remove_vertex(&seeded_location(0)).unwrap();
    crdt.remove_vertex(&seeded_location(1)).unwrap();
    crdt.commit(2).unwrap();
    let shard_id = GLOBAL_APP.to_vec();

    for phase in 0..4 {
        assert!(
            crdt.missing_vertex_blobs(&shard_id, phase).unwrap().is_empty(),
            "phase {phase} of a self-materialized shard with removes must audit clean",
        );
    }
}

/// THE COST BUG THIS GUARDS: a leaf no peer can serve must not keep an
/// O(leaves) sweep plus one RPC per gap running on every sync tick forever.
///
/// The live case is a STALE LEAF — this node's tree has not converged, so it
/// commits to a revision the peer no longer holds and the commitment binding
/// correctly rejects the peer's current blob. Measured on L1: 4915 of 5124 gaps
/// filled, 209 permanently unfillable, and under the original "only a fully
/// filled audit marks the tree clean" rule those 209 re-ran the entire
/// nine-and-a-half-minute pass on every tick.
#[test]
fn an_unfillable_leaf_is_offered_once_and_then_skipped() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 3, 1);
    let shard_id = GLOBAL_APP.to_vec();
    let follower = fresh_crdt();
    sync_prover_phase0(&follower, leader.clone());

    let missing = follower.pending_blob_repairs(&shard_id, 0).unwrap();
    assert_eq!(missing.len(), 3, "a tree-only install leaves every leaf without data");

    // A peer serves one of the three; the other two it cannot.
    let blobs = fetch_repair_blobs(&leader, &missing[..1]);
    follower.install_vertex_blobs(&shard_id, 0, &blobs).unwrap();
    for (key_hash, leaf_value) in &missing[1..] {
        follower.mark_blob_unfillable(&shard_id, 0, *key_hash, leaf_value.clone());
    }

    // The raw audit still reports them — it is the honest answer about data.
    assert_eq!(
        follower.missing_vertex_blobs(&shard_id, 0).unwrap().len(),
        2,
        "the audit must not lie about a leaf having no readable data",
    );
    // The repair list does not: there is nothing left to spend an RPC on.
    assert!(
        follower.pending_blob_repairs(&shard_id, 0).unwrap().is_empty(),
        "an already-refused leaf must not be requested again",
    );
}

/// The skip is bound to the LEAF VALUE, not the leaf. A leaf that was
/// unfillable because our tree was behind comes back into scope the moment the
/// tree moves it on — otherwise one transient miss would suppress the repair
/// for that vertex for the rest of the process.
#[test]
fn a_moved_leaf_is_offered_again_after_being_marked_unfillable() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 2, 1);
    let shard_id = GLOBAL_APP.to_vec();
    let follower = fresh_crdt();
    sync_prover_phase0(&follower, leader.clone());

    let missing = follower.pending_blob_repairs(&shard_id, 0).unwrap();
    assert_eq!(missing.len(), 2);
    for (key_hash, leaf_value) in &missing {
        follower.mark_blob_unfillable(&shard_id, 0, *key_hash, leaf_value.clone());
    }
    assert!(follower.pending_blob_repairs(&shard_id, 0).unwrap().is_empty());

    // The leader rewrites vertex 0 and the follower's tree converges onto the
    // new leaf value. The stale verdict no longer describes this leaf.
    leader.add_vertex(&seeded_location(0), b"rewritten payload for vertex 0").unwrap();
    leader.commit(2).unwrap();
    sync_prover_phase0(&follower, leader.clone());

    // The leaf's `key_hash` IS the vertex's data address, so name it directly
    // rather than relying on the sweep's ordering.
    let again = follower.pending_blob_repairs(&shard_id, 0).unwrap();
    assert_eq!(again.len(), 1, "only the leaf that moved is offered again");
    assert_eq!(again[0].0, seeded_location(0).data_address);
}
