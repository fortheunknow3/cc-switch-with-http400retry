//! Opt-in raw outbound-body capture for the Claude -> OpenAI Responses path.
//!
//! This debug facility exists to reproduce a specific gateway incompatibility
//! offline: it writes the exact serialized bytes sent upstream, including the
//! full conversation, so they can be replayed and bisected locally.
//!
//! Safety properties:
//! - Disabled unless `CC_SWITCH_CAPTURE_RESPONSES_BODY` is truthy, and only
//!   invoked while the request-conversion diagnostics switch is on.
//! - Writes only into `<app config dir>/logs/request-captures/` (the cleanup
//!   path refuses any other directory name) and keeps the newest entries only.
//! - Never logs request content, only byte counts and file paths.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const CAPTURE_DIR_NAME: &str = "request-captures";
const ENV_VAR: &str = "CC_SWITCH_CAPTURE_RESPONSES_BODY";
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CAPTURED_FILES: usize = 40;

fn parse_enabled(raw: Option<&str>) -> bool {
    raw.map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
    .unwrap_or(false)
}

pub(crate) fn capture_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let enabled = parse_enabled(std::env::var(ENV_VAR).ok().as_deref());
        if enabled {
            log::info!(
                "[RAW-CAPTURE] enabled via {ENV_VAR}; captures contain the full request body and stay on this machine"
            );
        }
        enabled
    })
}

fn sanitize_component(raw: &str, limit: usize) -> String {
    let mut out: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(limit)
        .collect();
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn capture_exists(dir: &Path, hash: &str) -> bool {
    let suffix = format!("-{hash}.json");
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(&suffix))
            })
        })
        .unwrap_or(false)
}

/// Keeps only the newest `keep` capture files (lexicographic order matches the
/// millisecond timestamp prefix) and ignores anything this module did not name.
fn prune(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut owned: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            if !entry.file_type().ok()?.is_file() {
                return None;
            }
            let name = entry.file_name().to_str().map(str::to_string)?;
            if !name.ends_with(".json") || !name.contains("-attempt") {
                return None;
            }
            Some((name, entry.path()))
        })
        .collect();
    if owned.len() <= keep {
        return;
    }
    owned.sort_by(|left, right| left.0.cmp(&right.0));
    let remove_count = owned.len() - keep;
    for (_, path) in owned.into_iter().take(remove_count) {
        if path.parent() != Some(dir) {
            continue;
        }
        if std::fs::remove_file(&path).is_err() {
            log::debug!("[RAW-CAPTURE] could not prune {}", path.display());
        }
    }
}

/// Writes one capture, deduplicating identical payloads and pruning old files.
///
/// Returns the written path; `None` means the write was skipped (wrong
/// directory, oversized payload, or an identical payload already exists).
fn write_capture(
    dir: &Path,
    request_id: &str,
    attempt: u32,
    bytes: &[u8],
    max_bytes: usize,
    keep: usize,
) -> Option<PathBuf> {
    // Refuse to operate unless the caller passed the capture directory itself;
    // this keeps every later cleanup confined to files this module created.
    if dir.file_name().and_then(|name| name.to_str()) != Some(CAPTURE_DIR_NAME) {
        return None;
    }
    if bytes.is_empty() || bytes.len() > max_bytes {
        return None;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let hash = crate::proxy::json_canonical::short_sha256_hex(bytes);
    if capture_exists(dir, &hash) {
        return None;
    }
    let file_name = format!(
        "{}-{}-attempt{}-{}.json",
        unix_millis(),
        sanitize_component(request_id, 64),
        attempt,
        hash
    );
    let path = dir.join(file_name);
    std::fs::write(&path, bytes).ok()?;
    prune(dir, keep);
    Some(path)
}

pub(crate) fn capture_outbound_body(request_id: &str, attempt: u32, bytes: &[u8]) {
    if !capture_enabled() {
        return;
    }
    let dir = crate::config::get_app_config_dir()
        .join("logs")
        .join(CAPTURE_DIR_NAME);
    if let Some(path) = write_capture(
        &dir,
        request_id,
        attempt,
        bytes,
        MAX_CAPTURE_BYTES,
        MAX_CAPTURED_FILES,
    ) {
        log::info!(
            "[RAW-CAPTURE] wrote {} bytes to {}",
            bytes.len(),
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_capture_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "cc-switch-capture-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique).join(CAPTURE_DIR_NAME);
        std::fs::create_dir_all(&dir).expect("create temp capture dir");
        dir
    }

    fn cleanup(dir: &Path) {
        if let Some(root) = dir.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn parse_enabled_accepts_truthy_spellings_only() {
        for raw in [Some("1"), Some("true"), Some(" ON "), Some("Yes")] {
            assert!(parse_enabled(raw), "{raw:?}");
        }
        for raw in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("maybe"),
        ] {
            assert!(!parse_enabled(raw), "{raw:?}");
        }
    }

    #[test]
    fn write_capture_stores_exact_bytes_and_dedupes_identical_payloads() {
        let dir = temp_capture_dir();
        let payload = br#"{"model":"deepseek/test","input":[]}"#;
        let first = write_capture(&dir, "req-1", 1, payload, 1024, 8).expect("first write");
        assert_eq!(std::fs::read(&first).unwrap(), payload);
        assert!(first
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("-attempt1-"));
        assert!(write_capture(&dir, "req-1", 2, payload, 1024, 8).is_none());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        cleanup(&dir);
    }

    #[test]
    fn write_capture_skips_oversized_payloads_and_foreign_directories() {
        let dir = temp_capture_dir();
        let large = vec![b'x'; 64];
        assert!(write_capture(&dir, "req-1", 1, &large, 32, 8).is_none());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let foreign = dir.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&foreign).unwrap();
        assert!(write_capture(&foreign, "req-1", 1, b"{}", 32, 8).is_none());
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 0);
        cleanup(&dir);
    }

    #[test]
    fn prune_keeps_newest_owned_entries_and_ignores_other_files() {
        let dir = temp_capture_dir();
        for index in 0..6u8 {
            let payload = vec![b'a' + index; 3];
            write_capture(&dir, "req", 1, &payload, 1024, 3).expect("write");
        }
        std::fs::write(dir.join("unrelated.json"), b"keep").unwrap();
        let owned: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| name.contains("-attempt"))
            .collect();
        assert_eq!(owned.len(), 3);
        assert!(std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name() == "unrelated.json"));
        cleanup(&dir);
    }
}
