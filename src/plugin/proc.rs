//! The sidecar's process-control layer: the pid walk, the Win32 effects behind
//! it, and the teardown order.
//!
//! The decision is DATA and the effect is a SEAM. [`descendants`] walks a
//! `(pid, parent_pid)` table, so a fixture pins the filter without a process
//! being touched; [`ProcOps`] performs the OS calls, and [`Win32ProcOps`] is the
//! only implementation that terminates anything.
//!
//! That split is a safety property, not a test convenience. A mutated filter
//! hands its pid list to `TerminateProcess`, which then kills every process the
//! test user can open — the shell, the per-user services, the editor and the
//! campaign running it — and the machine reads as logged out.
//!
//! Test rule: `Win32ProcOps` is only ever handed a pid the test spawned and still
//! holds as a [`Child`], or a job the test created and filled. A pid that came
//! out of `descendants` goes to a fake, never to the real op.

use std::process::Child;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_SET_QUOTA, PROCESS_TERMINATE, TerminateProcess,
};

use crate::sandbox::Job;

/// Every pid whose recorded parent chain reaches `root`; `root` is never in it.
///
/// Windows does not re-parent, so the recorded parent id still names the original
/// parent after it exits: this walk finds an orphaned grandchild, which is
/// exactly what a launcher leaves behind.
///
/// `found` doubles as the cycle guard: a parent loop (impossible in a live
/// snapshot, trivial in a fixture) ends instead of spinning. Sorted, so callers
/// and tests read one order.
pub(super) fn descendants(root: u32, table: &[(u32, u32)]) -> Vec<u32> {
    let mut found: Vec<u32> = Vec::new();
    let mut frontier = vec![root];
    while let Some(pid) = frontier.pop() {
        for (child, parent) in table {
            if *parent == pid && *child != root && !found.contains(child) {
                found.push(*child);
                frontier.push(*child);
            }
        }
    }
    found.sort_unstable();
    found
}

/// The process-table effects the sidecar needs, behind one trait so a test can
/// answer from a table and record the calls instead of touching real processes.
pub(super) trait ProcOps {
    /// Live `(pid, parent_pid)` pairs, one snapshot per call.
    fn snapshot(&self) -> Vec<(u32, u32)>;

    /// Terminate one process by id, best-effort.
    ///
    /// A process that exited between the snapshot and this call makes
    /// `OpenProcess` fail, and that is a success for the property under test:
    /// the goal is "gone", not "we killed it".
    fn terminate(&self, pid: u32);

    /// Put `pid` in `job`, so `KILL_ON_JOB_CLOSE` covers it too.
    fn adopt(&self, job: &Job, pid: u32);

    /// The tree under `root`, from one snapshot.
    fn descendants(&self, root: u32) -> Vec<u32> {
        descendants(root, &self.snapshot())
    }
}

/// The Win32 implementation: ToolHelp snapshot, `TerminateProcess`, job adoption.
pub(super) struct Win32ProcOps;

impl ProcOps for Win32ProcOps {
    fn snapshot(&self) -> Vec<(u32, u32)> {
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        // SAFETY: the snapshot handle is closed on every path; each entry is
        // filled into a live `PROCESSENTRY32W` that outlives the call, and the
        // loop stops on the first error (which is how the API reports the end of
        // the enumeration).
        unsafe {
            let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return Vec::new();
            };
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        pairs
    }

    fn terminate(&self, pid: u32) {
        if let Some(handle) = open_pid(pid, PROCESS_TERMINATE) {
            // SAFETY: `open_pid` returned a live handle opened with
            // `PROCESS_TERMINATE`; it is closed immediately after the call.
            unsafe {
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }

    fn adopt(&self, job: &Job, pid: u32) {
        if let Some(handle) = open_pid(pid, PROCESS_SET_QUOTA | PROCESS_TERMINATE) {
            let _ = job.assign(handle);
            // SAFETY: the handle came from `open_pid` and is not used again.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

/// Open `pid` with exactly `rights`, or `None` when it is already gone.
///
/// One helper for every by-pid use keeps the "a process that exited is not an
/// error" rule in a single place.
fn open_pid(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Option<HANDLE> {
    // SAFETY: no inheritance is requested and the result is either a live handle
    // the caller closes or an error that is discarded.
    unsafe { OpenProcess(rights, false, pid).ok() }
}

/// Adopt a launcher's own children into `job`, until a pass finds nothing new.
///
/// Best-effort by design: the fallback for a refusal is the `Drop` walk, and a
/// sidecar that refuses to start because the OS would not nest a job would be a
/// worse trade than one whose crash-durability is weaker.
pub(super) fn join_tree(ops: &dyn ProcOps, job: &Job, root: u32) {
    let mut seen: Vec<u32> = Vec::new();
    for _ in 0..4 {
        let fresh: Vec<u32> = ops
            .descendants(root)
            .into_iter()
            .filter(|pid| !seen.contains(pid))
            .collect();
        if fresh.is_empty() {
            break;
        }
        for pid in &fresh {
            ops.adopt(job, *pid);
        }
        seen.extend(fresh);
    }
}

/// End a sidecar's whole tree, then kill and reap the child.
///
/// The order is the invariant. The parent chain is walked while the child is
/// still alive, so its pid cannot have been recycled into someone else's process
/// in the meantime; descendants go first because `TerminateProcess` never
/// cascades on Windows; the job is terminated next for anything created inside
/// that window; and `wait` is what makes "no orphan" true rather than likely —
/// `kill` only requests termination, and a sidecar that outlived its session
/// would still be holding a facade token nobody can revoke.
pub(super) fn tear_down(child: &mut Child, job: Option<Job>, ops: &dyn ProcOps) {
    let root = child.id();
    for _ in 0..8 {
        let live = ops.descendants(root);
        if live.is_empty() {
            break;
        }
        for pid in live {
            ops.terminate(pid);
        }
    }
    if let Some(job) = job {
        let _ = job.terminate();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The walk's filter, pinned on a table: the grandchild is named, and a
    /// process hanging off another parent is not.
    #[test]
    fn the_walk_names_a_grandchild_and_never_a_sibling() {
        let table = [
            (100, 0),
            (101, 100),
            (102, 100),
            (103, 101),
            (200, 1),
            (104, 200),
        ];
        assert_eq!(descendants(100, &table), vec![101, 102, 103]);
    }

    /// The root is a boundary, not a member: a process that names itself as its
    /// own parent must not enter the list.
    #[test]
    fn the_walk_never_names_its_root() {
        assert_eq!(descendants(100, &[(100, 100), (101, 100)]), vec![101]);
    }

    /// A parent loop ends instead of spinning. `found` is the guard, and a
    /// fixture can express what a live snapshot cannot.
    #[test]
    fn the_walk_ends_on_a_parent_cycle() {
        let table = [(100, 0), (101, 100), (102, 101), (101, 102)];
        assert_eq!(descendants(100, &table), vec![101, 102]);
    }

    /// A root with no children and an empty table give the same answer.
    #[test]
    fn a_root_with_no_children_names_nothing() {
        assert_eq!(descendants(100, &[(101, 102)]), Vec::<u32>::new());
    }
}
