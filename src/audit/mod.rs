//! US-4a audit core: hash-chain NDJSON leaves, canonicalization, hashing.
//! This module grows across tasks; for now it holds the pure canonicalization
//! logic. The existing writer code from US-3 is folded in by Task 5.
//!
//! ## Reserved event: `secret.inject` (D-5.2, not yet emitted)
//!
//! Schema (a complete leaf; `seq`/`ts`/`hash`/`parent` are added by
//! [`AuditWriter::append`], the caller supplies only `op` + `name`):
//!
//! ```json
//! {"op": "secret.inject", "name": "<secret-name>", "seq": <u64>, "ts": "<iso8601>", "hash": "<hex>", "parent": "<hex|null>"}
//! ```
//!
//! The `name` field identifies the secret being injected (e.g. an env var
//! name or a file path identifier). This schema is reserved for F-2
//! (credential injection), which is out of scope for ADR-0001. No emission
//! code exists yet; see [`SECRET_INJECT_SCHEMA`] for the machine-checked
//! contract.

pub mod filter;
pub mod session_start;
pub mod show;
pub mod verify;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{MOVE_FILE_FLAGS, MoveFileExW};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::{HRESULT, HSTRING};

/// Reserved schema template for the `secret.inject` audit event (D-5.2).
/// Kept as a const so future F-2 emission code and tests share a single
/// source of truth; no production call site consumes it yet (only tests
/// reference it), so it is `#[allow(dead_code)]` until F-2 lands. See the
/// module-level doc comment for the full schema description.
#[allow(dead_code)]
pub const SECRET_INJECT_SCHEMA: &str =
    r#"{"op": "secret.inject", "name": "<secret-name>", "seq": <u64>, "ts": "<iso8601>", "hash": "<hex>", "parent": "<hex|null>"}"#;

/// Session ids are a path component: `audit_log_path` pastes one into
/// `%LOCALAPPDATA%\saife\audit\<sid>.ndjson`, and the root/signature files are
/// named the same way. `--sid` took whatever the caller passed, so a CI wrapper
/// doing `--sid "$PR_TITLE"` could write (and overwrite) files outside that
/// directory as the user. Restricted to the alphabet the generator already uses:
/// letters, digits, dot, underscore, hyphen - and never a bare `.` or `..`.
pub fn validate_session_id(session_id: &str) -> anyhow::Result<()> {
    if session_id.is_empty() || session_id.len() > 64 {
        anyhow::bail!("session id must be 1..=64 characters, got {}", session_id.len());
    }
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        anyhow::bail!(
            "session id may only contain letters, digits, '.', '_' and '-': {session_id:?}"
        );
    }
    if session_id == "." || session_id == ".." {
        anyhow::bail!("session id must name a file, not a directory: {session_id:?}");
    }
    Ok(())
}

/// Validate a session id and return it normalized (L-F): lower-cased.
///
/// Every intake point - the writer ([`AuditWriter::open`]), both readers
/// (`show`/`verify`) and the commit - goes through this, so the on-disk file
/// name and the leaf's `sid` field always agree byte for byte. NTFS resolves
/// `ABC.ndjson` and `abc.ndjson` to the same file, and a case-sensitive
/// comparison then turned a tool-created id (`ABC`) verified case-insensitively
/// (`abc`) into a self-inflicted `TAMPERED`. Legacy logs written with a
/// mixed-case leaf are still accepted: the leaf comparison is
/// case-insensitive (H4/L-F fix in `verify`).
pub fn normalize_session_id(session_id: &str) -> anyhow::Result<String> {
    validate_session_id(session_id)?;
    Ok(session_id.to_ascii_lowercase())
}

pub fn audit_log_path(session_id: &str) -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = local.join("saife").join("audit");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{session_id}.ndjson"))
}

/// The per-session exclusion file that sits next to the log (H5a). Appended
/// rather than a `with_extension` swap so it can never collide with the
/// committed `<sid>.root` / `<sid>.sig` pair.
pub fn lock_path(log_path: &std::path::Path) -> PathBuf {
    let file_name = log_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "session.ndjson".to_string());
    log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("{file_name}.lock"))
}

#[derive(Debug, Clone, Copy)]
#[cfg(test)]
pub enum Disposition { Allow, Deny }

#[cfg(test)]
impl Disposition {
    fn as_str(&self) -> &'static str { match self { Self::Allow => "allow", Self::Deny => "deny" } }
}

#[cfg(test)]
pub fn emit_connect(
    session_id: &str,
    host: &str,
    port: u16,
    disposition: Disposition,
    reason: Option<&str>,
) {
    let writer = AuditWriter::open(session_id, false).unwrap();
    let mut event = Map::new();
    event.insert("op".into(), serde_json::json!("CONNECT"));
    event.insert("host".into(), serde_json::json!(host));
    event.insert("port".into(), serde_json::json!(port));
    event.insert("disposition".into(), serde_json::json!(disposition.as_str()));
    event.insert("reason".into(), serde_json::json!(reason));
    writer.append(event).unwrap();
}

/// H5a: the per-session exclusion a writer holds for its whole lifetime.
///
/// The chain state is process-local, and `--sid` is caller-supplied, so two
/// overlapping runs on one session id each scanned the same file, each kept its
/// own `seq`/`last`, and interleaved their leaves - after which `verify` reported
/// `TAMPERED` on a log nobody edited. One writer per log, enforced across
/// processes by an `O_EXCL`-style publish of `<log>.lock` that names its holder.
///
/// Reaping follows `sandbox::dacl_journal`: a lock is stale only when its PID is
/// gone *or* the PID was reused by a different process (creation time differs).
/// A crashed run must not lock its session out forever, and a live run must never
/// have its lock taken away.
struct ChainLock {
    path: PathBuf,
    /// Cleared by [`AuditWriter::seal`] so `Drop` does not delete a lock that a
    /// *later* run has since taken.
    held: AtomicBool,
}

/// On-disk lock content. `created` is the raw process creation FILETIME, the
/// PID-reuse guard value.
#[derive(serde::Serialize, serde::Deserialize)]
struct LockRecord {
    pid: u32,
    created: i64,
}

impl ChainLock {
    /// Take the lock for `log_path`.
    ///
    /// `Ok(Some(_))` holds exclusion. `Ok(None)` is the documented non-strict
    /// degradation: the lock file could not be created at all (the directory is
    /// missing or unwritable), which means the log cannot be written either, so
    /// the writer is inert either way. **Contention is never degraded**: a live
    /// holder - or a lock file whose owner cannot be read - is an error in both
    /// modes, because proceeding would fork the chain that H5a closed.
    fn acquire(log_path: &Path, strict: bool) -> Result<Option<Self>> {
        let lock = lock_path(log_path);
        let sid = log_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| log_path.display().to_string());
        let record = serde_json::to_string(&LockRecord {
            pid: std::process::id(),
            created: crate::sandbox::dacl_journal::current_process_creation_time(),
        })
        .expect("LockRecord is always serializable");
        let tmp = lock.with_extension(format!(
            "lock.tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        // Two attempts: the first may reap a dead holder's file, the second takes
        // the lock. A third means something keeps republishing under us, which is
        // contention, not staleness.
        for _ in 0..2 {
            if let Err(e) = std::fs::write(&tmp, &record) {
                if strict {
                    return Err(anyhow::anyhow!(
                        "create audit lock {:?}: {e} (session {sid})",
                        lock.display()
                    ));
                }
                return Ok(None);
            }
            let published = unsafe {
                // flags = 0: no MOVEFILE_REPLACE_EXISTING. The destination's
                // existence is the exclusion; overwriting it would be the bug.
                MoveFileExW(
                    &HSTRING::from(tmp.as_os_str()),
                    &HSTRING::from(lock.as_os_str()),
                    MOVE_FILE_FLAGS(0),
                )
            };
            match published {
                Ok(()) => {
                    return Ok(Some(Self {
                        path: lock,
                        held: AtomicBool::new(true),
                    }));
                }
                // ERROR_ALREADY_EXISTS: someone holds it (or a killed run left it).
                Err(e) if e.code() == HRESULT::from_win32(183) => {
                    let _ = std::fs::remove_file(&tmp);
                    let holder = match std::fs::read_to_string(&lock)
                        .map_err(|e| e.to_string())
                        .and_then(|s| {
                            serde_json::from_str::<LockRecord>(&s).map_err(|e| e.to_string())
                        }) {
                        Ok(h) => h,
                        Err(why) => {
                            // An unreadable lock is not provably stale. Refusing is
                            // loud and names the remedy; guessing forks the chain.
                            return Err(anyhow::anyhow!(
                                "audit session {sid} has an unreadable lock {:?} ({why}); \
                                 if no saife session is running, delete that file",
                                lock.display()
                            ));
                        }
                    };
                    if holder_is_alive(&holder) {
                        return Err(anyhow::anyhow!(
                            "audit session {sid} is locked by running process {} ({:?}); \
                             refusing to open a second writer on the same chain",
                            holder.pid,
                            lock.display()
                        ));
                    }
                    // Dead holder: remove the stale file and try once more.
                    let _ = std::fs::remove_file(&lock);
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    if strict {
                        return Err(anyhow::anyhow!(
                            "publish audit lock {:?}: {e} (session {sid})",
                            lock.display()
                        ));
                    }
                    return Ok(None);
                }
            }
        }
        Err(anyhow::anyhow!(
            "audit session {sid} lock {:?} keeps reappearing; refusing to open a second writer",
            lock.display()
        ))
    }

    /// Stop excluding: [`AuditWriter::seal`] ends the chain, so it ends the lock.
    fn release(&self) {
        if self.held.swap(false, Ordering::SeqCst) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for ChainLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Is the lock's owner still the process that wrote it? Creation time is the
/// PID-reuse guard; `created == 0` (the holder could not read its own creation
/// time) falls back to a bare liveness check, which errs toward refusing rather
/// than toward forking a live session's chain.
fn holder_is_alive(holder: &LockRecord) -> bool {
    if holder.created != 0 {
        return crate::sandbox::dacl_journal::is_process_alive(holder.pid, holder.created);
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, holder.pid) };
    match handle {
        Ok(h) => {
            unsafe {
                let _ = CloseHandle(h);
            }
            true
        }
        Err(_) => false,
    }
}

pub struct AuditWriter {
    path: PathBuf,
    /// Parent hash AND next sequence number behind one lock. They are one
    /// invariant: seq must increase in file order, and the parent link must name
    /// the leaf written immediately before. Splitting them (a mutex for the hash,
    /// an atomic for seq) let two appends observe the same `None` parent and
    /// produced leaves that `verify` reported as TAMPERED - the tool accusing its
    /// own untouched log. Hold this guard across compute -> write -> commit.
    chain: Mutex<ChainState>,
    strict: bool,
    /// Stamped into every leaf. It is what makes a log belong to a session: without
    /// it, a clean session's three files can be copied over another's names and
    /// `audit verify` reports OK for the substitute.
    session_id: Option<String>,
    /// H5a: the per-session exclusion, held from open to drop (or seal).
    lock: Option<ChainLock>,
    /// H5c: leaves that arrived after [`AuditWriter::seal`] and were dropped so
    /// the file cannot grow past its committed root. `append` still returns
    /// `Ok(())` (its return type is a contract dozens of call sites rely on),
    /// so this counter is how the loss stops being silent: [`seal_audit`] reads
    /// it at session end and prints it.
    dropped_after_seal: AtomicU64,
}

/// The chain's commit point. Only `append` mutates this, and only under the lock.
#[derive(Default)]
struct ChainState {
    last: Option<String>,
    seq: u64,
    /// Set by [`AuditWriter::seal`]. A sealed chain accepts no further leaves, so the
    /// root and the file cannot disagree - the proxy's shutdown flush used to append
    /// AFTER the root was captured, and `verify` then reported the session TAMPERED.
    sealed: bool,
}

impl AuditWriter {
    /// Open the writer for a session. If the log file already exists (e.g.
    /// `--reuse <sid>` or crash recovery), scan existing lines to recover
    /// `last_hash` and `seq`. If it doesn't exist, start fresh.
    ///
    /// When `strict` is true, returns `Err` if the audit directory can't be
    /// created or the log file can't be opened for writing. When `strict`
    /// is false, degrades gracefully (best-effort logging, never returns
    /// `Err`).
    pub fn open(session_id: &str, strict: bool) -> Result<Self> {
        let session_id = normalize_session_id(session_id)?;
        let path = audit_log_path(&session_id);
        Self::open_at(path, strict)
    }

    /// Internal: open at an explicit path (for testing strict mode without
    /// env var manipulation).
    fn open_at(path: PathBuf, strict: bool) -> Result<Self> {
        if strict {
            // Verify the parent directory exists / can be created before claiming
            // the writer is usable (and before taking the lock, which lives there).
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Err(anyhow::anyhow!("create audit dir {:?}: {e}", parent.display()))
                    .with_context(|| "strict audit: directory not writable");
            }
        }

        // H5a: one writer per chain. Taken before the log is scanned, so `seq` and
        // `last` cannot be read from under another process's appends.
        let lock = ChainLock::acquire(&path, strict)?;

        if strict {
            // Touch the file to confirm it can be opened for appending. This
            // also surfaces permission errors eagerly instead of at the first
            // `append`.
            if let Err(e) = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
            {
                return Err(anyhow::anyhow!("open audit log {:?}: {e}", path.display()))
                    .with_context(|| "strict audit: log file not writable");
            }
        }

        // An existing log that cannot be scanned must NOT be extended: appending
        // with a `null` parent to a chain that already has leaves is exactly the
        // shape `verify` reports as tampering, so it would manufacture the verdict
        // it is supposed to detect. Refusing keeps the evidence honest and the
        // operator moves the file aside deliberately.
        let chain = if path.exists() {
            let (last, seq) = scan_existing(&path).with_context(|| {
                format!(
                    "existing audit chain {:?} is unreadable or corrupt; refusing to extend it \
                     (move it aside to start a new session)",
                    path.display()
                )
            })?;
            // H5b: a continuation invalidates the root committed for the shorter
            // log. Leaving a stale `<sid>.root` means `verify` compares the longer
            // chain against a root that does not match and calls the honest log
            // `TAMPERED`. Drop the pair now; the run's own commit publishes a fresh
            // one at exit (and an interrupted run leaves an honest INCOMPLETE).
            if seq > 0 {
                for ext in ["root", "sig"] {
                    let stale = path.with_extension(ext);
                    // No `exists()` pre-check: the pair may vanish between check and
                    // removal, and a missing file is the state we want either way.
                    match std::fs::remove_file(&stale) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            if strict {
                                return Err(anyhow::anyhow!(
                                    "remove stale audit {:?} (continuing chain {:?}): {e}",
                                    stale.display(),
                                    path.display()
                                ))
                                .with_context(|| "strict audit: could not clear the prior root");
                            }
                            // Non-strict: the run's own commit overwrites the stale
                            // pair at exit, so a removal failure here only bites if
                            // the run is then interrupted - and that is INCOMPLETE,
                            // not silent.
                        }
                    }
                }
            }
            ChainState { last, seq, sealed: false }
        } else {
            ChainState::default()
        };
        let session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string);
        Ok(Self {
            path,
            chain: Mutex::new(chain),
            strict,
            session_id,
            lock,
            dropped_after_seal: AtomicU64::new(0),
        })
    }

    /// Append a leaf. `event` is the op-specific payload (op, host, path,
    /// etc.) WITHOUT seq/ts/hash/parent — those are computed here.
    ///
    /// When `strict` is true, returns `Err` if the file can't be opened for
    /// appending or the write fails. When `strict` is false, silently
    /// swallows errors (best-effort) and always returns `Ok(())`.
    pub fn append(&self, mut event: Map<String, Value>) -> Result<()> {
        let mut chain = self.chain.lock().unwrap_or_else(|p| p.into_inner());
        if chain.sealed {
            // Late append after the root was committed. Dropping the leaf keeps the
            // chain verifiable; the alternative was a file that grows past its own
            // root, which reads as tampering. The drop is counted (H5c): silently
            // losing the proxy's trailing refusal aggregate broke the "sums to the
            // true total" invariant with nothing in the output to say so.
            self.dropped_after_seal.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        let seq = chain.seq;
        let ts = iso8601_utc();
        event.insert("seq".into(), serde_json::json!(seq));
        event.insert("ts".into(), serde_json::json!(ts));
        if let Some(sid) = &self.session_id {
            event.insert("sid".into(), serde_json::json!(sid));
        }
        let canonical = canonicalize(&event);
        let hash = sha256_hex(&canonical);
        let parent = chain.last.clone();
        event.insert("hash".into(), serde_json::json!(hash));
        event.insert("parent".into(), serde_json::json!(parent));
        let mut line = serde_json::to_string(&event)
            .expect("a Map<String, Value> is always serializable; see canonicalize");
        line.push('\n');

        if std::env::var_os("SAIFE_DIAG").is_some() {
            eprint!("[proxy] {line}");
        }

        let pre_len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let file_result = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path);
        let written = if self.strict {
            let mut f = file_result
                .with_context(|| format!("strict audit: open {:?} for append", self.path.display()))?;
            f.write_all(line.as_bytes())
                .with_context(|| format!("strict audit: write {:?} failed", self.path.display()))?;
            true
        } else if let Ok(mut f) = file_result {
            // Best-effort: the error is swallowed (the documented contract) but
            // must not be mistaken for success. A `write_all` that failed partway
            // can leave a partial line; truncate it away so the next append starts
            // on a clean line boundary. A terminal partial line would also make
            // `scan_existing` refuse to extend the log after a restart, turning a
            // transient failure into a dead file.
            match f.write_all(line.as_bytes()) {
                Ok(()) => true,
                Err(_) => {
                    let _ = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&self.path)
                        .and_then(|t| t.set_len(pre_len));
                    false
                }
            }
        } else {
            // The open itself failed (e.g. the log turned read-only): nothing was
            // written, so there is nothing to truncate.
            false
        };
        // Commit last: a failed write must not advance the chain, or the next
        // leaf would name a parent that is not in the file. In non-strict mode
        // this turns an honest transient failure into a visible gap (a dropped
        // leaf), not a phantom parent that `verify` calls TAMPERED. Strict mode
        // already returned `Err` above.
        if written {
            chain.seq = seq + 1;
            chain.last = Some(hash);
        }
        Ok(())
    }

    /// Seal the chain and return its root. After this no leaf can be added, so the
    /// caller can commit the root knowing the file will not grow past it. This
    /// replaces "capture the root, then sleep 50 ms and hope".
    ///
    /// Sealing also releases the H5a lock: the chain is final, so the exclusion it
    /// protected has nothing left to protect, and holding it would refuse the next
    /// run on that session id for as long as this process lives.
    pub fn seal(&self) -> Option<String> {
        let mut chain = self.chain.lock().unwrap_or_else(|p| p.into_inner());
        chain.sealed = true;
        if let Some(lock) = &self.lock {
            lock.release();
        }
        chain.last.clone()
    }

    /// H5c: how many leaves arrived after [`AuditWriter::seal`] and were dropped.
    ///
    /// Non-zero means the session's file is short of what the process tried to
    /// record - the proxy's trailing refusal aggregate is the real case, because
    /// [`seal_audit`] seals before `ProxyHandle::drop` flushes it.
    pub fn dropped_after_seal(&self) -> u64 {
        self.dropped_after_seal.load(Ordering::SeqCst)
    }

    /// The current chain root (last leaf's hash). None if no leaves yet.
    ///
    /// Test-only since [`AuditWriter::seal`] took over the production path: reading the
    /// root without freezing the chain is exactly the race that produced TAMPERED.
    #[cfg(test)]
    pub fn current_root(&self) -> Option<String> {
        self.chain
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last
            .clone()
    }
}

/// Scan an existing .ndjson file to recover the last hash + next seq for
/// crash recovery / --reuse.
fn scan_existing(path: &std::path::Path) -> Result<(Option<String>, u64)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read existing chain {:?}", path.display()))?;
    let mut last_hash: Option<String> = None;
    let mut max_seq: Option<u64> = None;
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("parse existing chain {:?} (line {line_no})", path.display()))?;
        if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
            last_hash = Some(h.to_string());
        }
        if let Some(s) = v.get("seq").and_then(|x| x.as_u64()) {
            max_seq = Some(max_seq.map_or(s, |m| m.max(s)));
        }
    }
    let next_seq = max_seq.map_or(0, |m| m + 1);
    Ok((last_hash, next_seq))
}

fn iso8601_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    iso8601_from_unix(secs)
}

/// [`iso8601_utc`] with the clock taken out: the arithmetic is the part that can
/// be wrong, and `now()` cannot be pinned in a test. A mutant in here corrupts
/// every audit timestamp silently, so the split is what makes it testable.
fn iso8601_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z_off: i64) -> (i64, u32, u32) {
    let z = z_off + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Canonicalize a leaf for hashing: remove `hash` and `parent` keys, sort the
/// remaining keys alphabetically (via BTreeMap), serialize compactly (no
/// whitespace). Deterministic across implementations regardless of insertion
/// order.
pub fn canonicalize(leaf: &Map<String, Value>) -> String {
    let mut copy = leaf.clone();
    copy.remove("hash");
    copy.remove("parent");
    // serde_json::Map with the "preserve_order" feature off defaults to
    // BTreeMap-backed, producing alphabetical keys. But to be explicit and
    // safe across feature flags, route through a BTreeMap:
    let btree: std::collections::BTreeMap<String, Value> = copy.into_iter().collect();
    // Infallible by construction: the value is a map with string keys of
    // `serde_json::Value`, which has no failing representation. The previous
    // `unwrap_or_else(|_| "{}")` was worse than a panic - it committed
    // sha256("{}") as the leaf hash while `verify` recomputed the same string, so
    // the chain "verified" while no longer committing to the event body.
    serde_json::to_string(&btree).expect("Map<String, Value> is always serializable")
}

/// SHA-256 of the canonical bytes, returned as lowercase hex.
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        // Boundaries the two-term version of the algorithm gets wrong: the
        // pre-epoch branch, an era edge, a non-leap century and the month
        // rollovers. Each of these is a distinct arithmetic site in the body.
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(-719_468), (0, 3, 1));
        assert_eq!(civil_from_days(-719_467), (0, 3, 2));
        assert_eq!(civil_from_days(-25_508), (1900, 3, 1));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
    }

    #[test]
    fn iso8601_from_unix_known_values() {
        assert_eq!(iso8601_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_from_unix(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(iso8601_from_unix(86_400), "1970-01-02T00:00:00Z");
        // 2024-01-01T02:03:04Z
        assert_eq!(iso8601_from_unix(1_704_074_584), "2024-01-01T02:03:04Z");
        // leap days, including the century one: 2024-02-29 and 2000-02-29
        assert_eq!(iso8601_from_unix(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    /// H5b deletes a stale `<sid>.root`/`<sid>.sig` pair when a chain is
    /// CONTINUED (`seq > 0`). At `seq == 0` the log is a new chain, and the pair
    /// belongs to whoever wrote it - deleting it there would drop a root the run
    /// did not invalidate.
    #[test]
    fn a_new_chain_keeps_a_stale_root_pair() {
        let sid = format!(
            "test-root-keep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);
        // An existing but EMPTY log scans as (None, 0) - a new chain.
        std::fs::write(&path, "").expect("write the empty log");
        let root = path.with_extension("root");
        std::fs::write(&root, "stale-root").expect("write the stale root");
        let _writer = AuditWriter::open_at(path.clone(), true).expect("open a new chain");
        assert!(
            root.exists(),
            "a new chain (seq == 0) must not delete the root pair; only a continuation does"
        );
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_session_id_accepts_the_boundary_length_and_rejects_one_more() {
        let longest = "a".repeat(64);
        assert!(
            validate_session_id(&longest).is_ok(),
            "64 characters is the documented maximum, so it must be accepted"
        );
        let too_long = "a".repeat(65);
        assert!(
            validate_session_id(&too_long).is_err(),
            "65 characters must be refused, or the id can overrun its file name"
        );
    }

    /// `created == 0` means the holder could not read its own creation time; the
    /// liveness check then falls back to a bare `OpenProcess` probe. Inverting
    /// that comparison sends the record into the creation-time-exact check
    /// instead, which can never match for 0 - so a LIVE holder reads as dead and
    /// its chain is reaped out from under it.
    #[test]
    fn a_lock_record_without_a_creation_time_still_probes_the_process() {
        let holder = LockRecord {
            pid: std::process::id(),
            created: 0,
        };
        assert!(
            holder_is_alive(&holder),
            "the current process is alive; a created == 0 record must still probe it"
        );
    }

    #[test]
    fn emit_connect_produces_valid_json() {
        // Use a temp session id so we don't collide with real sessions.
        let sid = format!("test-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        emit_connect(&sid, "api.anthropic.com", 443, Disposition::Allow, None);
        emit_connect(&sid, "evil.example.com", 443, Disposition::Deny, Some("domain_not_allowed"));
        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("line is valid JSON");
            assert_eq!(v["op"], "CONNECT");
            assert!(v["host"].as_str().unwrap().contains("anthropic.com") || v["host"].as_str().unwrap().contains("evil.example.com"));
            assert_eq!(v["port"], 443);
        }
        // The deny line must have a reason field.
        let deny_line: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(deny_line["disposition"], "deny");
        assert_eq!(deny_line["reason"], "domain_not_allowed");
    }

    #[test]
    fn emit_connect_escapes_malicious_host() {
        let sid = format!("test-escape-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        emit_connect(&sid, "evil\\\nhost", 443, Disposition::Deny, Some("a\"b"));
        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        // The event must occupy exactly one line in the file (no newline injection).
        let trimmed = content.strip_suffix('\n').unwrap_or(&content);
        let lines: Vec<&str> = trimmed.lines().collect();
        assert_eq!(lines.len(), 1, "event must occupy exactly one line");

        // The single line must parse as valid JSON.
        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("line is valid JSON");
        assert_eq!(v["host"], "evil\\\nhost", "host backslash + newline preserved literally");
        assert_eq!(v["reason"], "a\"b", "reason quote preserved literally");
        assert_eq!(v["port"], 443);
        assert_eq!(v["disposition"], "deny");
    }

    #[test]
    fn canonicalize_strips_hash_and_parent() {
        let m: Map<String, Value> = [
            ("op", Value::String("CONNECT".into())),
            ("host", Value::String("a.com".into())),
            ("hash", Value::String("deadbeef".into())),
            ("parent", Value::Null),
        ].iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        let v: Value = serde_json::from_str(&c).unwrap();
        assert!(v.get("hash").is_none());
        assert!(v.get("parent").is_none());
        assert_eq!(v["op"], "CONNECT");
    }

    #[test]
    fn canonicalize_is_alphabetical() {
        let m: Map<String, Value> = [
            ("op", Value::String("X".into())),
            ("host", Value::String("a".into())),
        ].iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        // "host" sorts before "op"
        let host_pos = c.find("\"host\"").unwrap();
        let op_pos = c.find("\"op\"").unwrap();
        assert!(host_pos < op_pos);
    }

    #[test]
    fn canonicalize_is_compact() {
        let m: Map<String, Value> = [("op", Value::String("X".into()))]
            .iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        assert!(!c.contains(' '), "no whitespace: got {c:?}");
        assert_eq!(c, "{\"op\":\"X\"}");
    }

    #[test]
    fn canonicalize_is_insertion_order_independent() {
        let mut m1: Map<String, Value> = Map::new();
        m1.insert("a".to_string(), Value::String("1".into()));
        m1.insert("b".to_string(), Value::String("2".into()));
        let mut m2: Map<String, Value> = Map::new();
        m2.insert("b".to_string(), Value::String("2".into()));
        m2.insert("a".to_string(), Value::String("1".into()));
        assert_eq!(canonicalize(&m1), canonicalize(&m2));
    }

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_chain_links_correctly() {
        let sid = format!("test-chain-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let writer = AuditWriter::open(&sid, false).unwrap();
        let mut e1 = Map::new();
        e1.insert("op".into(), serde_json::json!("CONNECT"));
        e1.insert("host".into(), serde_json::json!("a.com"));
        writer.append(e1).unwrap();
        let mut e2 = Map::new();
        e2.insert("op".into(), serde_json::json!("CONNECT"));
        e2.insert("host".into(), serde_json::json!("b.com"));
        writer.append(e2).unwrap();

        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let l1: Value = serde_json::from_str(lines[0]).unwrap();
        let l2: Value = serde_json::from_str(lines[1]).unwrap();

        // First leaf: parent is null.
        assert_eq!(l1["parent"], Value::Null);
        let h1 = l1["hash"].as_str().unwrap();

        // Second leaf: parent == hash of first.
        assert_eq!(l2["parent"], h1);

        // seq monotonic from 0.
        assert_eq!(l1["seq"], 0);
        assert_eq!(l2["seq"], 1);

        // Recompute hash of leaf 1 from its canonical body.
        let m1 = l1.as_object().unwrap().clone();
        let c1 = canonicalize(&m1);
        let recomputed1 = sha256_hex(&c1);
        assert_eq!(recomputed1, h1);
    }

    #[test]
    fn scan_existing_recovers_state() {
        let sid = format!("test-scan-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            for host in ["a", "b", "c"] {
                let mut e = Map::new();
                e.insert("op".into(), serde_json::json!("CONNECT"));
                e.insert("host".into(), serde_json::json!(host));
                w.append(e).unwrap();
            }
        }
        let path = audit_log_path(&sid);
        let (last_hash, next_seq) = scan_existing(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(last_hash.is_some());
        assert_eq!(next_seq, 3);
    }

    #[test]
    fn secret_inject_schema_is_reserved() {
        // References SECRET_INJECT_SCHEMA so it isn't flagged dead_code; also
        // pins the reserved `secret.inject` event contract (D-5.2) so an
        // accidental rename or drop is caught. See the module doc comment for
        // the full schema.
        assert!(SECRET_INJECT_SCHEMA.contains("\"op\""), "schema must name the op field");
        assert!(SECRET_INJECT_SCHEMA.contains("\"secret.inject\""), "schema must reserve the secret.inject op");
        assert!(SECRET_INJECT_SCHEMA.contains("\"name\""), "schema must include the name field");
        // Hash-chain fields are added by AuditWriter::append; the schema
        // template should enumerate them so the contract is explicit.
        for key in ["\"seq\"", "\"ts\"", "\"hash\"", "\"parent\""] {
            assert!(
                SECRET_INJECT_SCHEMA.contains(key),
                "schema must enumerate the {key} hash-chain field"
            );
        }
    }

    #[test]
    fn strict_open_fails_on_unwritable_path() {
        // Block `create_dir_all` by placing a regular file where a directory
        // is required: a file at `blocker`, then a log path of
        // `blocker/subdir/test.ndjson`. `create_dir_all` can't make a
        // directory inside a file, so strict open must fail. Reliable on
        // every platform (no env-var or drive-letter assumptions).
        let mut blocker_parent = std::env::temp_dir();
        blocker_parent.push(format!(
            "sandbox-audit-blocker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let blocker_file = blocker_parent.join("blocker");
        std::fs::create_dir_all(&blocker_parent).unwrap();
        std::fs::write(&blocker_file, b"x").unwrap();

        let log_path = blocker_file.join("subdir").join("test.ndjson");

        // Strict mode MUST refuse: create_dir_all fails because `blocker`
        // is a file, not a directory.
        let strict_res = AuditWriter::open_at(log_path.clone(), true);
        assert!(strict_res.is_err(), "strict open must fail on unwritable path");

        // Non-strict mode degrades gracefully (never returns Err).
        let lenient_res = AuditWriter::open_at(log_path, false);
        assert!(lenient_res.is_ok(), "non-strict open must degrade gracefully");

        // Clean up the blocker file + parent dir.
        let _ = std::fs::remove_file(&blocker_file);
        let _ = std::fs::remove_dir_all(&blocker_parent);
    }

    #[test]
    fn strict_append_fails_on_write_error() {
        // Open strict on a writable path inside a dedicated subdir we own,
        // then delete the whole subdir so the next `append` can't reopen the
        // file. Strict mode must surface that as `Err`; non-strict mode must
        // swallow it and return `Ok(())`.
        let mut own_dir = std::env::temp_dir();
        own_dir.push(format!(
            "sandbox-audit-strict-append-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&own_dir).unwrap();
        // Two logs, not two writers on one log: since H5a a second writer on the
        // same chain is refused by design, and this test is about append-failure
        // reporting, not about exclusion.
        let strict_log = own_dir.join("strict.ndjson");
        let lenient_log = own_dir.join("lenient.ndjson");

        let strict_writer =
            AuditWriter::open_at(strict_log, true).expect("strict open in own dir succeeds");
        let lenient_writer =
            AuditWriter::open_at(lenient_log, false).expect("non-strict open in own dir succeeds");

        // Delete the dedicated dir + its file. Now append can't open the
        // file (parent dir is gone).
        let _ = std::fs::remove_dir_all(&own_dir);

        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("a.com"));

        let strict_res = strict_writer.append(e.clone());
        assert!(strict_res.is_err(), "strict append must fail when file can't be opened");

        let lenient_res = lenient_writer.append(e);
        assert!(lenient_res.is_ok(), "non-strict append must swallow the write error");

        // No cleanup needed: own_dir was already removed.
    }

    /// The chain is the product's evidence. Two appends that interleave must still
    /// produce ONE chain: seq in file order, every parent naming the previous leaf.
    /// This failed before the writer kept `last` and `seq` behind one lock - both
    /// threads read `None` and `verify` called the result tampered.
    #[test]
    fn concurrent_appends_produce_one_verifiable_chain() {
        use crate::audit::verify::{VerifyOutcome, verify_inner};
        use std::sync::Arc;

        let sid = format!(
            "test-concurrent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let mut threads = Vec::new();
            for t in 0..4 {
                let w = Arc::clone(&writer);
                threads.push(std::thread::spawn(move || {
                    for i in 0..25 {
                        let mut e = Map::new();
                        e.insert("op".into(), serde_json::json!("CONNECT"));
                        e.insert("host".into(), serde_json::json!(format!("t{t}-{i}.example")));
                        w.append(e).unwrap();
                    }
                }));
            }
            for h in threads {
                h.join().unwrap();
            }
        }

        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let (mut expected_seq, mut prev, mut leaves) = (0u64, None::<String>, 0);
        for line in content.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                v["seq"].as_u64().unwrap(),
                expected_seq,
                "seq must follow file order even under concurrency"
            );
            assert_eq!(
                v["parent"].as_str().map(str::to_string),
                prev,
                "every leaf's parent must name the leaf written before it"
            );
            prev = v["hash"].as_str().map(str::to_string);
            expected_seq += 1;
            leaves += 1;
        }
        assert_eq!(leaves, 100, "no leaf may be lost");
        assert!(
            !matches!(verify_inner(&sid).unwrap(), VerifyOutcome::Tampered(_)),
            "an untampered log must never verify as tampered"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt existing log is evidence, not a starting point. Extending it would
    /// emit a null parent after real leaves - the exact shape `verify` reports as
    /// tampering - so the writer refuses and leaves the bytes alone.
    #[test]
    fn an_unreadable_existing_chain_is_refused_not_extended() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "sandbox-audit-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.ndjson");
        let original = "{\"op\":\"CONNECT\"}\nnot json at all\n";
        std::fs::write(&path, original).unwrap();

        let err = match AuditWriter::open_at(path.clone(), false) {
            Ok(_) => panic!("a corrupt chain must not be reopened for appending"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("refusing to extend"),
            "the refusal must say what to do: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "refusing must not touch the evidence"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The id becomes a file name, so it is validated where it is used rather than
    /// at one of the two CLI call sites.
    #[test]
    fn a_session_id_that_is_a_path_is_refused() {
        for bad in ["../escape", "a/b", "a\\b", "..", ".", "", &"x".repeat(65), "sp ace"] {
            assert!(
                validate_session_id(bad).is_err(),
                "{bad:?} must not be accepted as a session id"
            );
        }
        for good in ["20261025-133000-12345", "test_sid.1", "A-b_c"] {
            assert!(validate_session_id(good).is_ok(), "{good:?} is a normal id");
        }
        // And the writer refuses at its door, not just the helper.
        let err = match AuditWriter::open("../escape", false) {
            Ok(_) => panic!("a traversal id must not reach the filesystem"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("session id"), "the refusal must say why: {err}");
    }

    /// L-F (verdict doc: confirmed, Low). The id becomes a file name, and NTFS
    /// resolves `ABC` and `abc` to the same file; a leaf stamped with the raw
    /// casing made `verify` call the tool's own untouched log TAMPERED. Intake
    /// lowercases, so the name and the leaf always agree.
    #[test]
    fn a_session_id_is_lower_cased_at_intake() {
        let sid = format!(
            "TEST-CASE-INTAKE-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let lower = sid.to_ascii_lowercase();
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), serde_json::json!("CONNECT"));
            e.insert("host".into(), serde_json::json!("case.example"));
            w.append(e).unwrap();
        }
        let path = audit_log_path(&lower);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let leaf: Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(
            leaf["sid"], lower,
            "the leaf must stamp the normalized id, not the raw casing"
        );
    }

    /// Sealing is a state, not a sleep. Once sealed, a late append must not reach the
    /// file, or the log grows past the root that was committed for it and `verify`
    /// calls an honest session tampered.
    ///
    /// H5c: the refused leaf is also *counted*, so the loss is visible at session
    /// end (`seal_audit` prints the count) instead of silently breaking the proxy's
    /// "sums to the true total" invariant.
    #[test]
    fn a_sealed_chain_refuses_later_leaves() {
        let sid = format!(
            "test-sealed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let writer = AuditWriter::open(&sid, false).unwrap();
        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("a.example"));
        writer.append(e.clone()).unwrap();
        assert_eq!(
            writer.dropped_after_seal(),
            0,
            "nothing is dropped before the seal"
        );

        let root = writer.seal().expect("a chain with one leaf has a root");
        let path = audit_log_path(&sid);
        let bytes_before = std::fs::metadata(&path).unwrap().len();

        // A late refusal-aggregate flush, exactly as the proxy's Drop does it.
        let mut late = Map::new();
        late.insert("op".into(), serde_json::json!("CONNECT"));
        late.insert("host".into(), serde_json::json!("late.example"));
        writer.append(late).unwrap();
        // ... and a second one, because the window is not single-shot.
        let mut later = Map::new();
        later.insert("op".into(), serde_json::json!("CONNECT"));
        later.insert("host".into(), serde_json::json!("later.example"));
        writer.append(later).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            bytes_before,
            "a sealed chain must not grow"
        );
        assert_eq!(
            writer.dropped_after_seal(),
            2,
            "every leaf dropped after the seal is counted, so the loss is reportable"
        );
        assert_eq!(writer.seal().as_deref(), Some(root.as_str()), "the root is stable");
        assert!(
            !matches!(
                crate::audit::verify::verify_inner(&sid).unwrap(),
                crate::audit::verify::VerifyOutcome::Tampered(_)
            ),
            "the sealed chain must not verify as tampered"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// H5a (verdict doc: confirmed). `ChainState` is process-local and `--sid` is
    /// caller-supplied, so two overlapping runs on one sid each scanned the same
    /// file, each kept its own `seq`/`last`, and interleaved their leaves. `verify`
    /// then called the unedited log `TAMPERED` - the tool accusing its own evidence.
    /// One writer per sid, held for the writer's lifetime; the second open fails
    /// closed and names the holder.
    #[test]
    fn a_second_writer_on_a_live_session_is_refused() {
        let sid = format!(
            "test-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);
        let first = AuditWriter::open(&sid, false).expect("the first writer takes the chain");

        let err = match AuditWriter::open(&sid, false) {
            Ok(_) => panic!("a second writer on a live chain must be refused, not forked"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains(&std::process::id().to_string()),
            "the refusal must name the holding PID: {err}"
        );
        assert!(
            err.to_ascii_lowercase().contains("lock"),
            "the refusal must name the lock: {err}"
        );
        // Strict mode is the posture the proxy runs in, and it must fail closed the
        // same way: an audit writer that cannot guarantee exclusion is not strict.
        assert!(
            AuditWriter::open(&sid, true).is_err(),
            "strict mode must refuse a held chain too"
        );

        // The holder is unaffected, and its chain still verifies.
        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("held.example"));
        first.append(e).expect("the holder keeps appending");

        drop(first);
        // Lifetime, not a timeout: the lock goes away with the writer.
        {
            let reopened =
                AuditWriter::open(&sid, false).expect("the lock is released when its writer drops");
            drop(reopened);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    /// A killed run leaves its lock file behind. Honouring it would deadlock every
    /// later run on that sid, so the holder is checked the same way the DACL journal
    /// checks its owner: the PID must be alive *and* still the same process instance.
    #[test]
    fn a_stale_lock_from_a_dead_process_is_reaped_not_honoured() {
        let sid = format!(
            "test-lock-stale-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);
        let lock = lock_path(&path);
        // PID 4294967294 and creation time 1: no such process, and no PID-reuse
        // window can match it (a real FILETIME is never 1).
        std::fs::write(&lock, r#"{"pid":4294967294,"created":1}"#).unwrap();

        let writer = AuditWriter::open(&sid, false).expect("a dead holder's lock must be reaped");
        let content = std::fs::read_to_string(&lock)
            .expect("the reaped lock must be replaced by the new holder's");
        assert!(
            content.contains(&std::process::id().to_string()),
            "the new lock must name this process, got {content:?}"
        );

        drop(writer);
        assert!(!lock.exists(), "Drop removes the lock file");
        let _ = std::fs::remove_file(&path);
    }

    /// Sealing finalises the chain, so the exclusion it protected is over: the lock
    /// must not outlive it or the next run on that sid would be refused forever.
    #[test]
    fn sealing_releases_the_lock() {
        let sid = format!(
            "test-lock-seal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);
        let writer = AuditWriter::open(&sid, false).unwrap();
        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("a.example"));
        writer.append(e).unwrap();
        assert!(
            lock_path(&path).exists(),
            "the live writer holds a lock file"
        );

        writer.seal().expect("one leaf has a root");
        assert!(
            !lock_path(&path).exists(),
            "seal ends the chain, so it ends the exclusion too"
        );
        let next = AuditWriter::open(&sid, false).expect("a sealed chain can be reopened");
        drop(next);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    /// H5b, second half. A continued chain (crash recovery, `--reuse`, or simply a
    /// second run on the same `--sid`) invalidates the root committed for the
    /// shorter log: leaving it in place means `verify` compares the longer chain
    /// against the shorter chain's root and calls an honest log `TAMPERED`.
    ///
    /// `open_at` now drops the stale pair the moment it detects a continuation, and
    /// the run's own commit publishes a fresh one at exit.
    #[test]
    fn continuing_a_chain_drops_the_root_committed_for_the_shorter_log() {
        use crate::audit::verify::{VerifyOutcome, verify_inner};

        let sid = format!(
            "test-continue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);
        let root_path = path.with_extension("root");
        let sig_path = path.with_extension("sig");

        // A clean, sealed, committed session.
        let root = {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), serde_json::json!("CONNECT"));
            e.insert("host".into(), serde_json::json!("first.example"));
            w.append(e).unwrap();
            w.seal().expect("one leaf has a root")
        };
        crate::commit_audit_root(&sid, &root).expect("commit the sealed root");
        assert!(
            matches!(verify_inner(&sid).unwrap(), VerifyOutcome::Ok),
            "the sealed session must verify before it is continued"
        );

        // The continuation. Its first act must be to invalidate the shorter log's
        // root, before any leaf is added under it.
        let w = AuditWriter::open(&sid, false).expect("a sealed chain can be continued");
        assert!(
            !root_path.exists(),
            "continuing a chain must drop the root committed for the shorter log"
        );
        assert!(
            !sig_path.exists(),
            "the stale signature goes with the stale root"
        );

        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("second.example"));
        w.append(e).unwrap();
        drop(w);

        // No root is committed for the longer log, so the honest verdict is
        // INCOMPLETE - never the accusation.
        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(_) => {}
            VerifyOutcome::Tampered(m) => {
                panic!("a continued chain must not verify as tampered: {m}")
            }
            other => panic!("expected Incomplete for an uncommitted continuation, got {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    /// H5d (verdict: confirmed, understated). A non-strict write failure is
    /// swallowed, but the chain still advanced — so the next successful leaf
    /// named a parent that was never written to the file, and `verify`
    /// reported TAMPERED on an honestly degraded log. The fix: on a non-strict
    /// write failure, do not advance seq/last (honour the existing comment at
    /// the commit point). Best-effort still returns `Ok(())`.
    #[test]
    fn a_failed_nonstrict_write_does_not_advance_the_chain() {
        use crate::audit::verify::{VerifyOutcome, verify_inner};

        let sid = format!(
            "test-h5d-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = audit_log_path(&sid);

        // Leaf A — writes successfully.
        let writer = AuditWriter::open(&sid, false).unwrap();
        let mut ea = Map::new();
        ea.insert("op".into(), serde_json::json!("CONNECT"));
        ea.insert("host".into(), serde_json::json!("a.example"));
        writer.append(ea).unwrap();

        // Capture A's hash for the parent assertion later.
        let content_a = std::fs::read_to_string(&path).unwrap();
        let leaf_a: Value = serde_json::from_str(content_a.lines().next().unwrap()).unwrap();
        let hash_a = leaf_a["hash"].as_str().unwrap().to_string();

        // Force the next append to fail WITHOUT changing code paths: make the
        // log file read-only so OpenOptions::append fails. On Windows the
        // readonly attribute denies FILE_APPEND_DATA; on Unix a 0o444 mode
        // denies write. The original permissions are restored afterwards
        // (rather than calling `set_readonly(false)`, which would make the file
        // world-writable on Unix and trips clippy::permissions_set_readonly_false).
        let original_perms = std::fs::metadata(&path).unwrap().permissions();
        let mut ro_perms = original_perms.clone();
        ro_perms.set_readonly(true);
        std::fs::set_permissions(&path, ro_perms).unwrap();

        // Leaf B — non-strict append must return Ok (best-effort contract)
        // even though the write failed.
        let mut eb = Map::new();
        eb.insert("op".into(), serde_json::json!("CONNECT"));
        eb.insert("host".into(), serde_json::json!("b.example"));
        let res_b = writer.append(eb);
        assert!(
            res_b.is_ok(),
            "non-strict append must swallow the write error (best-effort contract)"
        );

        // Restore the original permissions so writes succeed again.
        std::fs::set_permissions(&path, original_perms).unwrap();

        // Leaf C — writes successfully. Its parent must be hash(A), not
        // hash(B): B was never written to the file, so naming B as parent
        // would manufacture a TAMPERED verdict on an honest log.
        let mut ec = Map::new();
        ec.insert("op".into(), serde_json::json!("CONNECT"));
        ec.insert("host".into(), serde_json::json!("c.example"));
        writer.append(ec).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = content.trim().lines().collect();
        // Only A and C should be in the file — B was never written.
        assert_eq!(
            lines.len(),
            2,
            "only the two successful leaves should be in the file"
        );

        let leaf_c: Value = serde_json::from_str(lines[1]).unwrap();
        let parent_c = leaf_c["parent"].as_str().unwrap();
        assert_eq!(
            parent_c, hash_a,
            "C's parent must be hash(A) — B was never written, so naming B \
             would manufacture a phantom parent"
        );

        // The chain must not verify as tampered: it is an honest two-leaf
        // log. (No root/sig committed, so verify reports Incomplete, not
        // Tampered.)
        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(_) => {} // expected: no committed root
            VerifyOutcome::Tampered(m) => {
                panic!("an honestly degraded log must not verify as tampered: {m}")
            }
            other => panic!("expected Incomplete (no root), got {other:?}"),
        }
    }
}
