//! Crash-safe journal for host-DACL mutations (MXC filesystem_dacl.rs pattern).
//! Every ACE is journaled BEFORE the Win32 apply call; teardown replays the
//! journal to restore the host; startup reaps journals orphaned by dead
//! owners. See docs/mxc-source-analysis.md F-C/F-D.
//!
//! Wired into run(): `main.rs` opens the journal per run and calls
//! `recover_orphans` at startup; `appcontainer::restore_all` re-applies the
//! recorded prior state.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

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
    /// Whether the granted ACE was inheritable (diagnostics; restore only
    /// needs to revoke it, which removes the ACE regardless of flags).
    pub inherit: bool,
    pub prior_aces: Vec<PriorAce>,
}

pub struct DaclJournal {
    file: PathBuf,
}

impl DaclJournal {
    /// Open (create) this run's journal. Header line is written first.
    /// The header identifies the owning run for orphan recovery (`read_header`
    /// re-derives it from the file); the struct doesn't need to carry it.
    pub fn open(dir: &Path, header: JournalHeader) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = dir.join(format!("{}.jsonl", header.run_id));
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)?;
        if f.metadata()?.len() == 0 {
            writeln!(f, "{}", serde_json::to_string(&header).unwrap())?;
            f.sync_all()?;
        }
        Ok(Self { file })
    }

    /// Journal an entry BEFORE the caller applies the ACE to the host.
    /// Append + fsync: a torn tail line is skipped by the parser, so a
    /// crash mid-write loses at most one not-yet-applied entry (safe:
    /// never applied => nothing to restore).
    pub fn record(&self, entry: &JournalEntry) -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap())?;
        f.sync_all()?;
        Ok(())
    }

    /// Journal a whole batch BEFORE the caller applies any of it (one
    /// open+write+fsync for the batch — a per-entry fsync is the dominant
    /// cost when propagation covers a multi-thousand-object tree). The
    /// crash contract holds at batch granularity: a torn tail line is
    /// skipped by the parser, so a crash loses at most the not-yet-applied
    /// remainder of the batch, and `restore_one` is idempotent against
    /// never-applied entries (revoking a never-granted trustee and
    /// re-merging already-present prior ACEs are no-ops).
    pub fn record_many(&self, entries: &[JournalEntry]) -> std::io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)?;
        let mut buf = String::new();
        for e in entries {
            buf.push_str(&serde_json::to_string(e).unwrap());
            buf.push('\n');
        }
        f.write_all(buf.as_bytes())?;
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

    /// Journal file path (for diagnostics and "retain on failed restore").
    pub fn path(&self) -> &Path {
        &self.file
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
    reap: &dyn Fn(&DaclJournal) -> bool,
) -> usize {
    let mut reaped = 0;
    let Ok(files) = fs::read_dir(dir) else {
        return 0;
    };
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
        let journal = DaclJournal { file: path };
        if reap(&journal) {
            journal.remove_file();
        }
        reaped += 1;
    }
    reaped
}

/// Default journal directory: `%LOCALAPPDATA%\sandbox\dacl-restore`
/// (sibling of the audit dir, same per-user convention).
pub fn default_dir() -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = local.join("sandbox").join("dacl-restore");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Raw FILETIME of this process's creation time (PID-reuse guard value).
pub fn current_process_creation_time() -> i64 {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        if GetProcessTimes(
            GetCurrentProcess(),
            &mut create,
            &mut exit,
            &mut kernel,
            &mut user,
        )
        .is_err()
        {
            return 0;
        }
    }
    filetime_to_i64(&create)
}

/// Is `pid` alive AND still the same process instance that owns `created`?
/// Real `is_alive` for `recover_orphans`: a journal belongs to a live run
/// only while its owner PID exists and its creation time is unchanged.
pub fn is_process_alive(pid: u32, created: i64) -> bool {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok =
        unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user).is_ok() }
            && filetime_to_i64(&create) == created;
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
    ok
}

fn filetime_to_i64(ft: &FILETIME) -> i64 {
    ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64)
}

fn read_header(path: &Path) -> Option<JournalHeader> {
    let first = fs::read_to_string(path).ok()?.lines().next()?.to_string();
    serde_json::from_str(&first).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sbx-journal-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn header(pid: u32) -> JournalHeader {
        JournalHeader {
            run_id: format!("r{pid}"),
            owner_pid: pid,
            owner_created: 0,
        }
    }

    fn entry(path: &str) -> JournalEntry {
        JournalEntry {
            path: path.into(),
            sid: "S-1-15-2-42".into(),
            granted_mask: 0x1f01ff,
            deny: false,
            protected: false,
            inherit: true,
            prior_aces: vec![PriorAce {
                deny: true,
                mask: 1,
                inherit_flags: 0,
            }],
        }
    }

    #[test]
    fn record_many_roundtrips_batch_in_order() {
        let d = tmpdir("batch");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        let entries: Vec<JournalEntry> = (0..3)
            .map(|i| entry(&format!("C:\\batch{i}")))
            .collect();
        j.record_many(&entries).unwrap();
        let read = j.entries();
        assert_eq!(read.len(), 3, "all batch entries journaled");
        assert_eq!(read[0].path, "C:\\batch0");
        assert_eq!(read[2].path, "C:\\batch2", "order preserved");
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
        let reaped = recover_orphans(&d, &|h| h.owner_pid == 4242, &|_| true);
        assert_eq!(reaped, 1, "dead-owner journal reaped exactly once");
        assert!(!d.join("r99999.jsonl").exists(), "dead journal deleted");
        assert!(d.join("r4242.jsonl").exists(), "live journal untouched");
    }

    #[test]
    fn unparseable_journal_is_quarantined_not_dropped() {
        let d = tmpdir("corrupt");
        fs::write(d.join("bad.jsonl"), "not json\n").unwrap();
        let reaped = recover_orphans(&d, &|_| false, &|_| true);
        assert_eq!(reaped, 0, "no reap of unparseable journal");
        assert!(
            d.join("bad.jsonl.corrupt").exists(),
            "quarantined for inspection"
        );
        assert!(!d.join("bad.jsonl").exists(), "original removed");
    }
}
