//! Opt-in diagnostics this node serves to peers its operator names. Every
//! feature is off by default and serves, when on, only this node itself and
//! the peers listed by ID; changes take effect on restart.
use serde::{Deserialize, Serialize};

/// Bounds of `diagnostics.healthReport.minIntervalSecs`.
pub const HEALTH_REPORT_INTERVAL_SECS: std::ops::RangeInclusive<u64> = 10..=3600;

fn default_min_interval_secs() -> u64 {
    60
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsConfig {
    /// A health report of this node's workers (phase, frames, recovery
    /// counts; no text, addresses or keys) on the peer gRPC listener.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub health_report: HealthReportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthReportConfig {
    /// Serve the report to the peers in `allowedPeers`.
    #[serde(default)]
    pub enabled: bool,
    /// Base58 peer IDs (a node's network identity, as `qclient node info`
    /// prints it) allowed to ask. This node itself is always allowed.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub allowed_peers: Vec<String>,
    /// Seconds before the same peer is served again (10..=3600).
    #[serde(default = "default_min_interval_secs")]
    pub min_interval_secs: u64,
}

impl Default for HealthReportConfig {
    fn default() -> Self {
        Self { enabled: false, allowed_peers: Vec::new(), min_interval_secs: default_min_interval_secs() }
    }
}

impl DiagnosticsConfig {
    /// Clamp the intervals into their bounds.
    pub fn apply_defaults(&mut self) {
        let interval = &mut self.health_report.min_interval_secs;
        *interval = (*interval).clamp(*HEALTH_REPORT_INTERVAL_SECS.start(), *HEALTH_REPORT_INTERVAL_SECS.end());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_report_is_off_with_no_peers_unless_configured() {
        for yaml in ["{}", "healthReport: null\n", "healthReport:\n  allowedPeers: null\n"] {
            let parsed: DiagnosticsConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(parsed, DiagnosticsConfig::default(), "{yaml}");
            assert!(!parsed.health_report.enabled && parsed.health_report.allowed_peers.is_empty());
            assert_eq!(parsed.health_report.min_interval_secs, 60);
        }
        let parsed: DiagnosticsConfig = serde_yaml::from_str(
            "healthReport:\n  enabled: true\n  allowedPeers: [QmPeerOne, QmPeerTwo]\n  minIntervalSecs: 120\n",
        )
        .unwrap();
        let report = &parsed.health_report;
        assert!(report.enabled);
        assert_eq!(report.allowed_peers, ["QmPeerOne", "QmPeerTwo"]);
        assert_eq!(report.min_interval_secs, 120);
        let encoded = serde_yaml::to_string(&parsed).unwrap();
        assert!(encoded.contains("healthReport:") && encoded.contains("allowedPeers:") && encoded.contains("minIntervalSecs: 120"));
        assert_eq!(serde_yaml::from_str::<DiagnosticsConfig>(&encoded).unwrap(), parsed);
    }

    #[test]
    fn the_interval_is_clamped() {
        for (configured, effective) in [(0, 10), (9, 10), (10, 10), (600, 600), (3600, 3600), (86_400, 3600)] {
            let mut config = DiagnosticsConfig::default();
            config.health_report.min_interval_secs = configured;
            config.apply_defaults();
            assert_eq!(config.health_report.min_interval_secs, effective, "{configured}");
        }
    }
}
