//! `qclient node log …` — view/clean node logs.
//!
//! The node writes `master.log` and `worker-N.log` (rotated as
//! `<name>.<timestamp>[.gz]`) to its log directory, `logger.path` or by
//! default `.log` under its config directory; with `path: none` it logs only
//! to stderr, which the system service captures (the systemd journal on
//! Linux, `node.err` under the log directory on macOS).

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Subcommand;

use crate::context::GlobalArgs;
use crate::{nodeconfig, system};

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// View the node log (last N lines, optionally following).
    View {
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u64,
        #[arg(short = 'f', long)]
        follow: bool,
        /// Core whose log to view: 0 is the master, N is worker N.
        #[arg(long, default_value_t = 0)]
        core: u32,
    },
    /// Delete rotated node logs (the live logs are kept).
    Clean,
}

pub fn run(global: GlobalArgs, cmd: &LogCommand) -> anyhow::Result<()> {
    match cmd {
        LogCommand::View { lines, follow, core } => view(&global, *lines, *follow, *core),
        LogCommand::Clean => clean(&global).map(|_| ()),
    }
}

/// The directory the node of the resolved config writes its log files to, or
/// `None` when it logs only to stderr.
pub(crate) fn configured_log_dir(global: &GlobalArgs) -> anyhow::Result<Option<PathBuf>> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let config_dir = nodeconfig::default_node_config_dir(network)?;
    let config = quil_config::load_config(&config_dir)
        .map_err(|e| anyhow::anyhow!("load config: {e}"))?;
    Ok(config.logger.log_dir(&config_dir))
}

/// The node's live log file name for `core` (as the node's logging names it).
fn log_file_name(core: u32) -> String {
    if core == 0 {
        "master.log".to_string()
    } else {
        format!("worker-{core}.log")
    }
}

/// Whether `name` is a rotated node log: `master.log.<suffix>` or
/// `worker-N.log.<suffix>`, never a live `.log`.
fn is_rotated_log(name: &str) -> bool {
    let Some((base, suffix)) = name.split_once(".log.") else {
        return false;
    };
    let worker = base.strip_prefix("worker-").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (base == "master" || worker) && !suffix.is_empty()
}

fn view(global: &GlobalArgs, lines: u64, follow: bool, core: u32) -> anyhow::Result<()> {
    let mut cmd = match configured_log_dir(global)? {
        Some(dir) => {
            let file = dir.join(log_file_name(core));
            if !file.exists() {
                anyhow::bail!("log file not found: {}", file.display());
            }
            let mut cmd = Command::new("tail");
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string()).arg(file);
            cmd
        }
        None if system::os_type() == "linux" => {
            // Stderr only: every core's lines are in the service's journal.
            let mut cmd = Command::new("journalctl");
            cmd.args(["--utc", "-o", "cat", "--no-pager", "-u", system::NODE_SERVICE_NAME]);
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string());
            cmd
        }
        None => {
            let file = Path::new(system::LOG_PATH).join("node.err");
            if !file.exists() {
                anyhow::bail!("the node logs to stderr only and {} is missing", file.display());
            }
            let mut cmd = Command::new("tail");
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string()).arg(file);
            cmd
        }
    };
    let status = cmd.status().map_err(|e| anyhow::anyhow!("run {:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        anyhow::bail!("{:?} exited with {status}", cmd.get_program());
    }
    Ok(())
}

/// Delete the rotated logs in the node's log directory; returns how many.
pub(crate) fn clean(global: &GlobalArgs) -> anyhow::Result<usize> {
    let Some(dir) = configured_log_dir(global)? else {
        println!("The node writes no log files (logger.path is none)");
        return Ok(0);
    };
    let removed = remove_rotated_logs(&dir)?;
    println!("Removed {removed} rotated log file(s) from {}", dir.display());
    Ok(removed)
}

fn remove_rotated_logs(dir: &Path) -> anyhow::Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !is_rotated_log(name) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => eprintln!("failed to remove {}: {e}", path.display()),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_logs_are_never_rotated_logs() {
        for rotated in ["master.log.20261017T120000.gz", "worker-3.log.20261017T120000", "worker-12.log.1"] {
            assert!(is_rotated_log(rotated), "{rotated}");
        }
        for kept in ["master.log", "worker-3.log", "node.log", "other.log.gz", "worker-.log.1", "worker-x.log.1"] {
            assert!(!is_rotated_log(kept), "{kept}");
        }
    }

    /// Cleaning removes the rotated logs only and keeps every live log and
    /// any other file.
    #[test]
    fn cleaning_keeps_live_logs() {
        let dir = std::env::temp_dir().join(format!("qclient-log-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let names = ["master.log", "master.log.20261017T120000.gz", "worker-2.log", "worker-2.log.20261017T120000.gz", "notes.txt"];
        for name in names {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        assert_eq!(remove_rotated_logs(&dir).unwrap(), 2);
        let mut left: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["master.log", "notes.txt", "worker-2.log"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
