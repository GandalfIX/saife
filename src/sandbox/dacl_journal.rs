//! Crash-safe journal for host-DACL mutations (MXC filesystem_dacl.rs pattern).
//! Every ACE is journaled BEFORE the Win32 apply call; teardown replays the
//! journal to restore the host; startup reaps journals orphaned by dead
//! owners. See docs/mxc-source-analysis.md F-C/F-D.
//!
//! Wired into the grant path by Task 3B of
//! docs/superpowers/plans/2026-09-16-mxc-derived-hardening.md, which is gated
//! on the ADR-0001 branch merging first (appcontainer.rs diverged between
//! trunk and ADR). Until then this module is intentionally uncalled.

// Justified + documented: consumed by Task 3B (see above); silencing the
// module is preferable to dead partial wiring in the grant path.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PriorAce {
    pub deny: bool,
    pub mask: u32,
    pub inherit_flags: u32,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JournalHeader {
    pub run_id: String,
    pub owner_pid: u32,
    /// Owner process creation time (PID-reuse guard), raw FILETIME i64.
    pub owner_created: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JournalEntry {
    pub path: String,
    pub sid: String,
    pub granted_mask: u32,
    pub deny: bool,
    pub protected: bool,
    pub prior_aces: Vec<PriorAce>,
}

pub struct DaclJournal {
    file: PathBuf,
    pub header: JournalHeader,
}

impl DaclJournal {
    /// Open (create) this run's journal. Header line is written first.
    pub fn open(dir: &Path, header: JournalHeader) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = dir.join(format!("{}.jsonl", header.run_id));
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&file)?;
        if f.metadata()?.len() == 0 {
            writeln!(f, "{}", serde_json::to_string(&header).unwrap())?;
            f.sync_all()?;
        }
        Ok(Self { file, header })
    }

    /// Journal an entry BEFORE the caller applies the ACE to the host.
    /// Append + fsync: a torn tail line is skipped by the parser, so a
    /// crash mid-write loses at most one not-yet-applied entry (safe:
    /// never applied => nothing to restore).
    pub fn record(&self, entry: &JournalEntry) -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.file)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap())?;
        f.sync_all()?;
        Ok(())
    }

    /// Every entry (header line excluded). Unparseable lines are skipped.
    pub fn entries(&self) -> Vec<JournalEntry> {
        fs::read_to_string(&self.file)
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn remove_file(&self) {
        let _ = fs::remove_file(&self.file);
    }
}

/// Startup recovery: for every journal in `dir` whose owner is no longer
/// alive, invoke `reap(&journal)` (restore its entries), then delete it.
/// Unparseable journals are quarantined as `.corrupt`, never silently
/// dropped. Returns the number of journals reaped. `is_alive` is injected
/// for tests (real impl: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
/// GetProcessTimes vs `owner_created`).
pub fn recover_orphans(
    dir: &Path,
    is_alive: &dyn Fn(&JournalHeader) -> bool,
    reap: &dyn Fn(&DaclJournal),
) -> usize {
    let mut reaped = 0;
    let Ok(files) = fs::read_dir(dir) else { return 0 };
    for f in files.flatten() {
        let path = f.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let Some(header) = read_header(&path) else {
            let _ = fs::rename(&path, path.with_extension("jsonl.corrupt"));
            continue;
        };
        if header.owner_pid == std::process::id() {
            continue;
        }
        if is_alive(&header) {
            continue;
        }
        let journal = DaclJournal { file: path, header };
        reap(&journal);
        journal.remove_file();
        reaped += 1;
    }
    reaped
}

fn read_header(path: &Path) -> Option<JournalHeader> {
    let first = fs::read_to_string(path).ok()?.lines().next()?.to_string();
    serde_json::from_str(&first).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("sbx-journal-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn header(pid: u32) -> JournalHeader {
        JournalHeader { run_id: format!("r{pid}"), owner_pid: pid, owner_created: 0 }
    }

    fn entry(path: &str) -> JournalEntry {
        JournalEntry {
            path: path.into(),
            sid: "S-1-15-2-42".into(),
            granted_mask: 0x1f01ff,
            deny: false,
            protected: false,
            prior_aces: vec![PriorAce { deny: true, mask: 1, inherit_flags: 0 }],
        }
    }

    #[test]
    fn record_before_apply_roundtrip() {
        let d = tmpdir("roundtrip");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        j.record(&entry("C:\\x")).unwrap();
        assert_eq!(j.entries().len(), 1);
        assert_eq!(j.entries()[0].sid, "S-1-15-2-42");
    }

    #[test]
    fn orphans_of_dead_owners_are_reaped_and_live_journals_kept() {
        let d = tmpdir("orphan");
        let dead = DaclJournal::open(&d, header(99999)).unwrap();
        dead.record(&entry("C:\\y")).unwrap();
        let _live = DaclJournal::open(&d, header(4242)).unwrap();
        let reaped = recover_orphans(&d, &|h| h.owner_pid == 4242, &|_| {});
        assert_eq!(reaped, 1, "dead-owner journal reaped exactly once");
        assert!(!d.join("r99999.jsonl").exists(), "dead journal deleted");
        assert!(d.join("r4242.jsonl").exists(), "live journal untouched");
    }

    #[test]
    fn unparseable_journal_is_quarantined_not_dropped() {
        let d = tmpdir("corrupt");
        fs::write(d.join("bad.jsonl"), "not json\n").unwrap();
        let reaped = recover_orphans(&d, &|_| false, &|_| {});
        assert_eq!(reaped, 0, "no reap of unparseable journal");
        assert!(d.join("bad.jsonl.corrupt").exists(), "quarantined for inspection");
        assert!(!d.join("bad.jsonl").exists(), "original removed");
    }
}
