//! Crash-safe journal for host-DACL mutations (MXC filesystem_dacl.rs pattern).
//! Every ACE is journaled BEFORE the Win32 apply call; teardown replays the
//! journal to restore the host; startup reaps journals orphaned by dead
//! owners. See docs/research/mxc-source-analysis.md F-C/F-D.
//!
//! Wired into run(): `main.rs` opens the journal per run and calls
//! `recover_orphans` at startup; `appcontainer::restore_all` re-applies the
//! recorded prior state.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{FILETIME, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
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
            writeln!(
                f,
                "{}",
                serde_json::to_string(&header).map_err(std::io::Error::other)?
            )?;
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
        writeln!(
            f,
            "{}",
            serde_json::to_string(entry).map_err(std::io::Error::other)?
        )?;
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
            buf.push_str(&serde_json::to_string(e).map_err(std::io::Error::other)?);
            buf.push('\n');
        }
        f.write_all(buf.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    /// Every entry (header line excluded). Unparseable LINES are skipped; an
    /// UNREADABLE file is an error, never an empty journal — `restore_or_warn`
    /// treats the error as a restore failure and keeps the journal so the next
    /// start retries, instead of reporting success while every granted ACE
    /// stays on the host (M4, security review 2026-11-09).
    pub fn entries(&self) -> std::io::Result<Vec<JournalEntry>> {
        let text = fs::read_to_string(&self.file)?;
        Ok(text
            .lines()
            .skip(1)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
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
/// dropped. **Unreadable** journals (a sharing violation, a locked file) are
/// neither quarantined nor deleted: they are kept for the next start, because
/// a read failure is not evidence of corruption and deleting them would strand
/// the granted ACEs the file records (M4). Returns the number of journals
/// actually reaped — a reap that reports failure keeps its journal and does
/// not count. `is_alive` is injected for tests (real impl:
/// OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + GetProcessTimes vs
/// `owner_created`).
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
        let header = match read_header(&path) {
            Ok(Some(h)) => h,
            // Readable, but the first line is not a header: quarantine for
            // inspection (the file was already unusable).
            Ok(None) => {
                let _ = fs::rename(&path, path.with_extension("jsonl.corrupt"));
                continue;
            }
            // Unreadable is NOT corrupt and NOT empty. Keep it: the ACEs it
            // records are still on the host, and the next start can retry.
            Err(e) => {
                eprintln!(
                    "[journal] WARN: cannot read {} ({e}); keeping it for the next start \
                     - its granted ACEs are still on the host",
                    path.display()
                );
                continue;
            }
        };
        if header.owner_pid == std::process::id() {
            continue;
        }
        let alive = is_alive(&header);
        if std::env::var_os("SAIFE_DIAG").is_some() {
            eprintln!(
                "[journal] {} {} (owner_pid={} owner_created={})",
                if alive { "keeping live journal" } else { "REAPING orphan journal" },
                path.display(),
                header.owner_pid,
                header.owner_created
            );
        }
        if alive {
            continue;
        }
        let journal = DaclJournal { file: path };
        // Count only a reap that actually succeeded: a failed restore keeps
        // the journal for the next start, so reporting it as reaped would
        // overstate what was cleaned up.
        if reap(&journal) {
            journal.remove_file();
            reaped += 1;
        } else {
            eprintln!(
                "[journal] WARN: restore failed for {}; journal retained for the next start",
                journal.path().display()
            );
        }
    }
    reaped
}

/// Default journal directory: `%LOCALAPPDATA%\saife\dacl-restore`
/// (sibling of the audit dir, same per-user convention).
pub fn default_dir() -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = local.join("saife").join("dacl-restore");
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
///
/// POLARITY: this answers "is the owner ALIVE", and that is what
/// `recover_orphans`'s first closure must pass. It was inverted at the call
/// site until 2026-11-11, which made every new supervisor reap LIVE runs'
/// journals (restoring their DACLs out from under them) and keep the dead
/// ones' files forever.
///
/// ZOMBIES: a process that has been killed still answers `OpenProcess` while
/// any handle to it stays open (the supervisor's killer keeps one, and so does
/// every test harness that started it). Its threads are gone and nothing will
/// ever restore its journal, so it is DEAD for recovery purposes; the
/// zero-timeout wait on the same handle tells the two apart, because only a
/// terminated process's object is signalled. The wait needs `SYNCHRONIZE` on
/// the handle, so the query-only open is the fallback for callers that may
/// not even wait.
pub fn is_process_alive(pid: u32, created: i64) -> bool {
    let (handle, can_wait) =
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        {
            Ok(h) => (h, true),
            Err(_) => (
                match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                    Ok(h) => h,
                    Err(_) => return false,
                },
                false,
            ),
        };
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok =
        unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user).is_ok() }
            && filetime_to_i64(&create) == created
            && (!can_wait || unsafe { WaitForSingleObject(handle, 0) != WAIT_OBJECT_0 });
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
    ok
}

fn filetime_to_i64(ft: &FILETIME) -> i64 {
    ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64)
}

/// Read the header line. `Ok(None)` = the file was read but its first line is
/// not a header (corrupt: quarantine it). `Err` = the file could not be read
/// at all (locked, permissions): NOT corrupt, and deleting it would strand the
/// ACEs it records, so the caller keeps it.
fn read_header(path: &Path) -> std::io::Result<Option<JournalHeader>> {
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok()))
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

    /// Hold `path` open with a share mode of 0, so every other open — including
    /// `fs::read_to_string` — fails with a sharing violation. That is what a
    /// journal locked by an AV scanner or a second writer looks like, and it is
    /// the "unreadable" case M4 is about. Dropping the guard releases it.
    struct ExclusiveLock(windows::Win32::Foundation::HANDLE);
    impl Drop for ExclusiveLock {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    fn exclusive_lock(path: &std::path::Path) -> ExclusiveLock {
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_GENERIC_READ, FILE_SHARE_MODE, OPEN_EXISTING,
        };
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
        }
        .expect("open the journal exclusively to simulate a locked file");
        ExclusiveLock(handle)
    }

    #[test]
    fn record_many_roundtrips_batch_in_order() {
        let d = tmpdir("batch");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        let entries: Vec<JournalEntry> = (0..3).map(|i| entry(&format!("C:\\batch{i}"))).collect();
        j.record_many(&entries).unwrap();
        let read = j.entries().unwrap();
        assert_eq!(read.len(), 3, "all batch entries journaled");
        assert_eq!(read[0].path, "C:\\batch0");
        assert_eq!(read[2].path, "C:\\batch2", "order preserved");
    }

    #[test]
    fn record_before_apply_roundtrip() {
        let d = tmpdir("roundtrip");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        j.record(&entry("C:\\x")).unwrap();
        assert_eq!(j.entries().unwrap().len(), 1);
        assert_eq!(j.entries().unwrap()[0].sid, "S-1-15-2-42");
    }

    /// M4 (security review 2026-11-09, confirmed): an unreadable journal must
    /// NOT read as an empty one. The bug: `entries()` swallowed the read
    /// error, `restore_all` then "restored" nothing, reported success, and
    /// teardown deleted the journal — leaving every granted ACE on the host
    /// forever, with the module comment claiming the opposite. This pins the
    /// journal's half of the contract; the teardown half lives in
    /// appcontainer.rs (`restore_or_warn` must return false).
    #[test]
    fn an_unreadable_journal_is_an_error_not_an_empty_inventory() {
        let d = tmpdir("unreadable");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        j.record(&entry("C:\\locked")).unwrap();
        let _hold = exclusive_lock(j.path());
        assert!(
            j.entries().is_err(),
            "a sharing violation on the journal must be an error, not Ok([]) - an empty \
             inventory would let teardown report success and delete the file"
        );
    }

    /// M4 teardown half: with the journal unreadable, `restore_or_warn` (the
    /// function main.rs calls at teardown) must report FAILURE, and the caller
    /// then keeps the file. Once readable again, a restore that succeeds is
    /// reported and the file may be removed by the caller.
    #[test]
    fn teardown_reports_failure_and_keeps_an_unreadable_journal() {
        let d = tmpdir("teardown-locked");
        let j = DaclJournal::open(&d, header(99996)).unwrap();
        j.record(&entry("C:\\locked")).unwrap();
        assert!(j.path().exists(), "the journal exists before teardown");

        let _hold = exclusive_lock(j.path());
        let ok = crate::sandbox::appcontainer::restore_or_warn(&j);
        assert!(
            !ok,
            "an unreadable journal must fail the teardown - restore_or_warn reported success \
             on an inventory it could not read"
        );
        // The teardown contract: `if ok { journal.remove_file() }` (main.rs).
        if ok {
            j.remove_file();
        }
        assert!(
            j.path().exists(),
            "an unreadable journal must survive teardown so the next start retries it"
        );
        assert!(
            !d.join("r99996.jsonl.corrupt").exists(),
            "an unreadable journal is not corrupt and must not be quarantined"
        );

        // Negative control: once the lock is gone, the same journal reads and
        // the restore path can succeed (the reap closure in the next test
        // exercises deletion on success).
        drop(_hold);
        assert!(
            j.entries().unwrap().len() == 1,
            "the journal is intact after the lock is released"
        );
    }

    /// The polarity contract the call site depends on: this predicate answers
    /// "is the owner ALIVE". Inverted at the call site (2026-11-11) it reaped
    /// live runs' journals and kept dead ones, which made a concurrent
    /// session lose the DACLs it was holding.
    #[test]
    fn a_live_process_is_alive_a_recycled_or_missing_one_is_not() {
        let me = std::process::id();
        let created = current_process_creation_time();
        assert!(created != 0, "the current process has a creation time");
        assert!(is_process_alive(me, created));
        // Same PID, different creation time: a recycled PID is a different
        // process, and its journal is not this run's to restore.
        assert!(!is_process_alive(me, created + 1));
        // PID 0 never opens: the dead branch.
        assert!(!is_process_alive(0, created));
    }

    #[test]
    fn a_killed_process_with_a_retained_handle_is_not_alive() {
        // A terminated process object lingers as long as some handle to it
        // stays open - the caller that started it typically holds one. This
        // is exactly the state a killed supervisor's harness leaves behind,
        // and it must read as DEAD: OpenProcess succeeds and the creation
        // time matches, but the object is signalled.
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "waitfor /t 30 never-signal-xyz"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the zombie-fixture child spawns");
        let pid = child.id();
        let created = {
            let handle = unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                    .expect("the fixture child opens while it runs")
            };
            let mut create = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) }
                .expect("a live child reports its times");
            let created = filetime_to_i64(&create);
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
            created
        };
        assert!(is_process_alive(pid, created), "the running child is alive");
        child.kill().expect("the fixture child is killable");
        child.wait().expect("the kill is observable");
        // The fixture still holds the child's handle here, so the process
        // object lingers: the zombie branch is exercised for real.
        assert!(
            !is_process_alive(pid, created),
            "a killed child with a retained handle is not an owner"
        );
        drop(child);
    }

    /// M4 startup half: `recover_orphans` must count `reaped` only when the
    /// reap actually succeeded, and keep (not quarantine) a journal it cannot
    /// read.
    #[test]
    fn a_failed_reap_is_not_counted_and_keeps_the_journal() {
        let d = tmpdir("failed-reap");
        let dead = DaclJournal::open(&d, header(99995)).unwrap();
        dead.record(&entry("C:\\y")).unwrap();
        let reaped = recover_orphans(&d, &|h| h.owner_pid == 4242, &|_| false);
        assert_eq!(
            reaped, 0,
            "a failed restore is not a reaped journal - the count must not overstate cleanup"
        );
        assert!(
            d.join("r99995.jsonl").exists(),
            "the failed reap must keep the journal for the next start"
        );
        // The success path still removes it.
        let reaped = recover_orphans(&d, &|h| h.owner_pid == 4242, &|_| true);
        assert_eq!(reaped, 1, "a successful reap counts exactly once");
        assert!(
            !d.join("r99995.jsonl").exists(),
            "the journal is removed on success"
        );
    }

    /// M4 startup half: a journal locked against reads is kept as-is — not
    /// quarantined (a read failure is not corruption), not reaped (its ACEs
    /// are still on the host), and it is still there for the next start.
    #[test]
    fn recover_orphans_keeps_an_unreadable_journal_without_quarantining_it() {
        let d = tmpdir("locked-recover");
        let dead = DaclJournal::open(&d, header(99994)).unwrap();
        dead.record(&entry("C:\\z")).unwrap();
        let _hold = exclusive_lock(dead.path());
        let reaped = recover_orphans(&d, &|_| false, &|_| true);
        drop(_hold);
        assert_eq!(reaped, 0, "an unreadable journal is not reaped");
        assert!(
            d.join("r99994.jsonl").exists(),
            "an unreadable journal is kept for the next start"
        );
        assert!(
            !d.join("r99994.jsonl.corrupt").exists(),
            "an unreadable journal must not be quarantined as corrupt"
        );
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

    /// L-O (verdict: partial): teardown ACE restore IS implemented through the
    /// journal. Prove the restore path runs (the reap closure is invoked and sees
    /// the journaled entry) and the journal is removed on success — the
    /// `main.rs:1044-1048` teardown sequence. `.sandbox/<sid>` dir removal is a
    /// separate, tracked gap and is deliberately not tested here.
    #[test]
    fn teardown_restore_runs_and_journal_is_removed_on_success() {
        let d = tmpdir("teardown");
        let j = DaclJournal::open(&d, header(99998)).unwrap();
        j.record(&entry("C:\\teardown")).unwrap();
        assert!(
            d.join("r99998.jsonl").exists(),
            "the journal exists before teardown"
        );

        let restore_ran = std::cell::Cell::new(false);
        let reaped = recover_orphans(&d, &|h| h.owner_pid != 99998, &|journal| {
            restore_ran.set(true);
            assert_eq!(
                journal.entries().unwrap().len(),
                1,
                "the restore path sees the journaled ACE"
            );
            true
        });
        assert_eq!(reaped, 1, "the dead-owner journal is reaped");
        assert!(
            restore_ran.get(),
            "the restore path must run before the journal is removed"
        );
        assert!(
            !d.join("r99998.jsonl").exists(),
            "the journal is removed on a successful restore"
        );
    }
}
