//! The slot's lifecycle: one session to a slot, and no slot outlives its owner.
//!
//! Four rules, from `docs/plans/2026-10-30-gradle-build-runner.md` (§3, T2.3-T2.5):
//!
//! * **One session per slot.** A slot records the session it belongs to *and* the process
//!   that created it (pid plus that process's creation time, so a recycled pid cannot adopt
//!   an old slot). A slot whose owner is alive belongs to that owner even when a second
//!   supervisor is handed the same session name: the second one is refused, never allowed to
//!   steal a container out from under a build.
//! * **A slot dies with its session** ([`SlotKeeper`]). Dropping it is the only thing that
//!   guarantees the Gradle daemon (measured 479 MB) does not outlive the run that created
//!   it, on every early return and on a panic.
//! * **A slot dies with its owner's crash too** ([`sweep`], at start-up) - and only then:
//!   removing a *live* session's slot would corrupt a build in progress, so liveness is the
//!   pid/creation-time pair, never "a container with that name exists".
//! * **An idle slot is not kept** ([`kill_idle`]): a warm attach costs 73 ms and a cold one
//!   1.67 s to 13.6 s, while the daemon costs 479 MB, so ten idle minutes is where the trade
//!   stops paying. Idle is read from a marker *inside* the container, which is what makes
//!   `saife runner status` in another process and the watchdog in this one date the slot the
//!   same way - a host-side table would be a second source of truth that can drift.
//!
//! The rules are pure functions over [`SlotFacts`] ([`decide`], [`idle_expired`],
//! [`idle_victims`], [`orphan_victims`]); the functions that execute them take an [`Engine`].
//! That split is what lets every rule be tested without a container running, and the live
//! legs then prove the same rules against the real engine.

use crate::runner::docker::{Engine, Slot, SlotFacts, SlotSpec};
use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Ten minutes, from the plan's §3 decision: the measured cost of keeping a slot alive is a
/// 479 MB daemon, and the measured cost of dropping it is one cold daemon start (1.67 s warm
/// page cache, 13.6 s cold) on the next build. Ten idle minutes is where those cross.
pub const IDLE_KILL: Duration = Duration::from_secs(10 * 60);

/// How many slots may be *running* at once.
///
/// Each live slot can hold a Gradle daemon (479 MB measured, one JVM), so this cap is about
/// the host's memory rather than about a clever container limit: four concurrent daemons is
/// ~2 GB, and the fifth session is refused by name instead of making the machine swap.
pub const MAX_SLOTS: usize = 4;

/// The idle window and the cap, as one value so a test (or a session) can override either
/// without a second knob somewhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotPolicy {
    pub idle: Duration,
    pub cap: usize,
}

impl Default for SlotPolicy {
    fn default() -> Self {
        SlotPolicy {
            idle: IDLE_KILL,
            cap: MAX_SLOTS,
        }
    }
}

/// What [`decide`] concluded about this session's slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The slot is exactly what the pin names and was used inside the idle window.
    Reuse(Slot),
    /// The slot must go first, and the reason is worth printing: it is the difference
    /// between "your build is slow because the daemon died" and a mystery.
    Recycle { slot: Slot, reason: String },
    /// This session has no slot; one has to be created.
    Create,
}

/// A slot ready to build in, plus why it had to be recreated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub slot: Slot,
    /// `Some(reason)` when a stale or idle slot was removed first, so the caller can say so in
    /// the build log instead of silently paying a cold daemon.
    pub recycle_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// The rules, as pure functions
// ---------------------------------------------------------------------------

/// Wall clock in unix seconds, the unit every fact here is expressed in (the engine reports
/// `Created` that way and `date +%s` inside the container does too).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Is the process that created a slot still the same process instance?
///
/// `created` is the PID-reuse guard: a slot recorded from pid 8120 must not be adopted by a
/// later process that happens to get pid 8120 again.
pub fn owner_is_alive(pid: u32, created: i64) -> bool {
    if pid == 0 {
        // No owner label: nothing owns it, so nothing here can be "still alive".
        return false;
    }
    if created == 0 {
        // The OS refused to report the creation time when the slot was made, so liveness
        // cannot be proven - and assuming dead would sweep a build in progress. Assume alive;
        // the cost of being wrong is one stale container, which `status` shows.
        return true;
    }
    crate::sandbox::dacl_journal::is_process_alive(pid, created)
}

/// Has this slot been idle for the whole window?
///
/// A slot we cannot date (`None`) is **not** idle: killing something we cannot date is how a
/// watchdog kills a build that happens to be longer than the window, and a cold prewarm fill
/// is measured at more than ten minutes.
pub fn idle_expired(last_use: Option<i64>, now: i64, idle: Duration) -> bool {
    match last_use {
        None => false,
        Some(used) if now >= used => now - used >= idle.as_secs() as i64,
        // A marker from the future is a clock problem, not idleness.
        Some(_) => false,
    }
}

/// The slots the idle kill may remove: running, not busy, and past the window.
pub fn idle_victims<'a>(
    facts: &'a [SlotFacts],
    policy: &SlotPolicy,
    now: i64,
    busy: &dyn Fn(&SlotFacts) -> bool,
) -> Vec<&'a SlotFacts> {
    facts
        .iter()
        .filter(|f| f.running && !busy(f) && idle_expired(f.last_use, now, policy.idle))
        .collect()
}

/// The slots a start-up sweep may remove: every one whose owner process is gone.
pub fn orphan_victims<'a>(
    facts: &'a [SlotFacts],
    alive: &dyn Fn(u32, i64) -> bool,
) -> Vec<&'a SlotFacts> {
    facts
        .iter()
        .filter(|f| !alive(f.owner_pid, f.owner_created))
        .collect()
}

/// What to do about this session's slot, decided from facts alone.
pub fn decide(
    facts: &[SlotFacts],
    spec: &SlotSpec,
    policy: &SlotPolicy,
    now: i64,
    alive: &dyn Fn(u32, i64) -> bool,
) -> Result<Decision> {
    // Mine is found by the session *label*, not the container name: the name is chosen by the
    // caller, the label is written by the create body and travels with the container.
    let mut mine: Option<&SlotFacts> = None;
    for f in facts.iter().filter(|f| f.session == spec.session) {
        // A crash between create and remove can leave a stopped duplicate; the running one is
        // the slot a build should land in.
        if mine.is_none_or(|m| !m.running && f.running) {
            mine = Some(f);
        }
    }

    if let Some(mine) = mine {
        // Ownership first: a slot labelled with this session but created by another *live*
        // process is that process's container, and adopting it would put two runners in one
        // build environment.
        if mine.owner_pid != spec.owner_pid || mine.owner_created != spec.owner_created {
            if alive(mine.owner_pid, mine.owner_created) {
                bail!(
                    "runner_slot_owned_elsewhere: slot {} is labelled with this session but \
                     belongs to pid {} (created {}), which is still running - one slot, one \
                     session",
                    mine.name,
                    mine.owner_pid,
                    mine.owner_created
                );
            }
            return Ok(Decision::Recycle {
                slot: mine.slot(),
                reason: format!(
                    "the owner process (pid {}, created {}) is gone",
                    mine.owner_pid, mine.owner_created
                ),
            });
        }
        // The pin is the audit: a digest that moved is a toolchain the operator did not
        // review, so the container that runs it is not the container they approved.
        if mine.image != spec.image {
            return Ok(Decision::Recycle {
                slot: mine.slot(),
                reason: format!(
                    "the pinned image moved: the slot was created from {}, the pin is now {}",
                    mine.image, spec.image
                ),
            });
        }
        if mine.jdk != spec.jdk {
            return Ok(Decision::Recycle {
                slot: mine.slot(),
                reason: format!(
                    "the pinned JDK moved: the slot was created for {}, the pin is now {}",
                    mine.jdk, spec.jdk
                ),
            });
        }
        if idle_expired(mine.last_use, now, policy.idle) {
            return Ok(Decision::Recycle {
                slot: mine.slot(),
                reason: format!(
                    "it has been idle for {} s (the idle kill is {} s)",
                    now - mine.last_use.unwrap_or(now),
                    policy.idle.as_secs()
                ),
            });
        }
        return Ok(Decision::Reuse(mine.slot()));
    }

    // No slot of my session. A *name* collision with another session's container is a
    // refusal rather than a retry: create would answer 409, and retrying around a 409 builds
    // in nothing at all (or in someone else's container).
    if let Some(theirs) = facts.iter().find(|f| f.name == spec.name)
        && alive(theirs.owner_pid, theirs.owner_created)
    {
        bail!(
            "runner_slot_owned_elsewhere: the slot name {} is held by session `{}` \
             (pid {}), which is still running",
            theirs.name,
            theirs.session,
            theirs.owner_pid
        );
    }

    // The cap counts *running* slots: a stopped container costs disk, not the 479 MB daemon
    // the cap exists to bound.
    let running = facts.iter().filter(|f| f.running).count();
    if running >= policy.cap {
        bail!(
            "runner_slot_cap_reached: {} slot(s) are running and the cap is {} - each live slot \
             can hold a Gradle daemon (479 MB measured), so the runner refuses to start another \
             rather than swap the machine; end a session or wait for the idle kill ({} s)",
            running,
            policy.cap,
            policy.idle.as_secs()
        );
    }

    Ok(Decision::Create)
}

// ---------------------------------------------------------------------------
// The rules, executed
// ---------------------------------------------------------------------------

/// Get this session's slot: reuse it when it is still what the pin names, otherwise recycle
/// it, otherwise create one - refusing past the cap.
pub fn admit(engine: &Engine, policy: &SlotPolicy, spec: &SlotSpec) -> Result<Admission> {
    let mut facts = engine.list_slot_facts()?;
    // Only my slot needs its marker read: another session's idle state is its own business,
    // and every read is an exec.
    read_markers(
        engine,
        facts
            .iter_mut()
            .filter(|f| f.session == spec.session && f.running),
    );

    match decide(&facts, spec, policy, now_unix(), &owner_is_alive)? {
        Decision::Reuse(slot) => {
            if !engine.slot_running(&slot)? {
                // `docker start` of a stopped container is 37 ms measured, cheaper than
                // create + start, and it keeps the container's own state.
                engine.start_slot(&slot)?;
            }
            // One session, one slot: a duplicate left by a crash between create and remove is
            // removed here, or the next build would find it again.
            for extra in facts
                .iter()
                .filter(|f| f.session == spec.session && f.slot_id != slot.id)
            {
                let _ = engine.remove_slot(&extra.slot());
            }
            touch(engine, &slot);
            Ok(Admission {
                slot,
                recycle_reason: None,
            })
        }
        Decision::Recycle { slot, reason } => {
            // Remove before create: the engine refuses a name that is still taken.
            engine.remove_slot(&slot)?;
            Ok(Admission {
                slot: create(engine, spec)?,
                recycle_reason: Some(reason),
            })
        }
        Decision::Create => Ok(Admission {
            slot: create(engine, spec)?,
            recycle_reason: None,
        }),
    }
}

/// Create and start a slot, and record that it is in use.
fn create(engine: &Engine, spec: &SlotSpec) -> Result<Slot> {
    // The cache is the whole reason a slot can build offline; a slot created without it looks
    // fine and then fails on the first dependency.
    engine.ensure_cache_volume()?;
    let slot = engine.create_slot(spec)?;
    engine.start_slot(&slot)?;
    touch(engine, &slot);
    Ok(slot)
}

/// Record the slot's last use. Bookkeeping only: a slot that cannot be dated is never
/// idle-killed, so a failure here must not fail the build it is recording.
fn touch(engine: &Engine, slot: &Slot) {
    let _ = engine.touch_slot(slot);
}

/// Read the last-use marker for each of `slots`, best effort.
fn read_markers<'a>(engine: &Engine, slots: impl Iterator<Item = &'a mut SlotFacts>) {
    for f in slots {
        f.last_use = engine.slot_last_use(&f.slot()).unwrap_or(None);
    }
}

/// Every slot of `session`, removed. The kill-on-end half of the ownership rule.
pub fn release(engine: &Engine, session: &str) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    for facts in engine.list_slot_facts()? {
        if facts.session != session {
            continue;
        }
        let slot = facts.slot();
        if engine.remove_slot(&slot).is_ok() {
            removed.push(slot.name);
        }
    }
    Ok(removed)
}

/// Holds a session's slots for exactly the session's lifetime.
///
/// `Drop` is the mechanism, not a courtesy: every early return between "the session started"
/// and "the workload exited" has to remove the slot, or the daemon outlives the run.
pub struct SlotKeeper {
    engine: Engine,
    session: String,
}

impl SlotKeeper {
    pub fn new(engine: Engine, session: &str) -> Self {
        SlotKeeper {
            engine,
            session: session.to_string(),
        }
    }
}

impl Drop for SlotKeeper {
    fn drop(&mut self) {
        let _ = release(&self.engine, &self.session);
    }
}

/// Every slot on the engine with its last-use marker read: the facts `saife runner status`
/// reports (`slot_id`, image digest, created-at, idle-since).
pub fn facts_for_status(engine: &Engine) -> Result<Vec<SlotFacts>> {
    let mut facts = engine.list_slot_facts()?;
    read_markers(engine, facts.iter_mut().filter(|f| f.running));
    Ok(facts)
}

/// Remove the slots idle past the window.
///
/// `only_session` narrows the reaping to one session, and the watchdog always passes it: a
/// slot of *another* session may be mid-build (a cold Gradle fill is measured at more than ten
/// minutes), and only its own runner knows that.
pub fn kill_idle(
    engine: &Engine,
    policy: &SlotPolicy,
    only_session: Option<&str>,
    now: i64,
    busy: &dyn Fn(&SlotFacts) -> bool,
) -> Result<Vec<String>> {
    let mut facts = engine.list_slot_facts()?;
    if let Some(session) = only_session {
        facts.retain(|f| f.session == session);
    }
    read_markers(engine, facts.iter_mut().filter(|f| f.running));

    let mut killed = Vec::new();
    for victim in idle_victims(&facts, policy, now, busy) {
        let slot = victim.slot();
        if engine.remove_slot(&slot).is_ok() {
            killed.push(slot.name);
        }
    }
    Ok(killed)
}

/// The start-up sweep: remove every slot whose owner process is gone.
///
/// Only orphans - a live session's slot is a build environment somebody is using, and removing
/// it is worse than leaving it until its own session ends or it goes idle.
pub fn sweep(engine: &Engine, alive: &dyn Fn(u32, i64) -> bool) -> Result<Vec<SlotFacts>> {
    let facts = engine.list_slot_facts()?;
    let mut swept = Vec::new();
    for victim in orphan_victims(&facts, alive) {
        let slot = victim.slot();
        if engine.remove_slot(&slot).is_ok() {
            swept.push(victim.clone());
        }
    }
    Ok(swept)
}

/// The idle kill on a timer, stopped by dropping the handle (which joins the thread, so no
/// reap can be in flight when the session tears down).
pub struct IdleWatchdog {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for IdleWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Reap `session`'s idle slots every `tick` until the handle is dropped.
///
/// `busy` answers "a build is running in this slot right now": the marker is written when a
/// slot is acquired, so a build that runs longer than the idle window would otherwise look
/// idle from inside its own session.
pub fn spawn_idle_watchdog(
    engine: Engine,
    policy: SlotPolicy,
    session: String,
    tick: Duration,
    busy: Arc<dyn Fn(&SlotFacts) -> bool + Send + Sync>,
) -> Result<IdleWatchdog> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let name = format!("saife-runner-idle-{session}");
    let join = std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            while wait_or_stop(&thread_stop, tick) {
                let now = now_unix();
                let _ = kill_idle(&engine, &policy, Some(&session), now, &|f: &SlotFacts| {
                    busy(f)
                });
            }
        })
        .context("runner: spawn the idle watchdog")?;
    Ok(IdleWatchdog {
        stop,
        join: Some(join),
    })
}

/// Sleep up to `dur`, returning `false` as soon as `stop` is set.
///
/// 100 ms slices: dropping the handle must not wait out a whole tick, and a tick is a
/// bookkeeping interval rather than a latency path.
fn wait_or_stop(stop: &AtomicBool, dur: Duration) -> bool {
    let deadline = std::time::Instant::now() + dur;
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::docker::{RUNNER_IMAGE, RUNNER_JDK};

    /// Fixed clock: every rule here is arithmetic on unix seconds, so it is tested at exact
    /// boundaries rather than with sleeps.
    const NOW: i64 = 1_700_000_200;

    fn spec(session: &str) -> SlotSpec {
        SlotSpec::new(session)
    }

    fn policy() -> SlotPolicy {
        SlotPolicy::default()
    }

    fn alive(_pid: u32, _created: i64) -> bool {
        true
    }

    fn dead(_pid: u32, _created: i64) -> bool {
        false
    }

    /// This session's own slot, running, on the current pin, used 100 s ago.
    fn mine(spec: &SlotSpec) -> SlotFacts {
        SlotFacts {
            slot_id: "id-mine".to_string(),
            name: spec.name.clone(),
            session: spec.session.clone(),
            image: spec.image.clone(),
            jdk: spec.jdk.clone(),
            created_at: NOW - 300,
            owner_pid: spec.owner_pid,
            owner_created: spec.owner_created,
            running: true,
            last_use: Some(NOW - 100),
        }
    }

    /// Another session's slot, with a live owner, running or not.
    fn foreign(session: &str, running: bool) -> SlotFacts {
        SlotFacts {
            slot_id: format!("id-{session}"),
            name: format!("saife-runner-{session}"),
            session: session.to_string(),
            image: RUNNER_IMAGE.to_string(),
            jdk: RUNNER_JDK.to_string(),
            created_at: NOW - 300,
            owner_pid: 8120,
            owner_created: 7,
            running,
            last_use: Some(NOW - 100),
        }
    }

    #[test]
    fn my_live_slot_on_the_pinned_digest_is_reused() {
        let s = spec("s1");
        let facts = vec![mine(&s)];
        assert_eq!(
            decide(&facts, &s, &policy(), NOW, &alive).expect("a decision"),
            Decision::Reuse(Slot {
                id: "id-mine".to_string(),
                name: s.name.clone()
            })
        );
    }

    /// Two slots labelled with one session is not a state the code creates, but a crash
    /// between create and remove can leave it; the running one is the one to reuse.
    #[test]
    fn a_running_slot_wins_over_a_stopped_duplicate_of_the_same_session() {
        let s = spec("s1");
        let mut running = mine(&s);
        running.slot_id = "id-running".to_string();
        let mut stopped = mine(&s);
        stopped.slot_id = "id-stopped".to_string();
        stopped.name = format!("{}-old", s.name);
        stopped.running = false;

        let facts = vec![stopped, running];
        match decide(&facts, &s, &policy(), NOW, &alive).expect("a decision") {
            Decision::Reuse(slot) => assert_eq!(slot.id, "id-running"),
            other => panic!("the running slot must be reused, got {other:?}"),
        }
    }

    /// The image is a digest, and a digest that moved means the toolchain inside the slot is
    /// no longer the toolchain the operator audited - a silent upgrade, if the slot is reused.
    #[test]
    fn a_slot_whose_image_digest_moved_is_recycled() {
        let s = spec("s1");
        let mut f = mine(&s);
        f.image = format!("eclipse-temurin@sha256:{}", "0".repeat(64));

        match decide(&[f], &s, &policy(), NOW, &alive).expect("a decision") {
            Decision::Recycle { reason, .. } => {
                assert!(
                    reason.contains("image"),
                    "the reason names the pin: {reason}"
                );
            }
            other => panic!("a moved digest must recycle the slot, got {other:?}"),
        }
    }

    /// The JDK version changes only with the image today, but the slot records it separately
    /// so a pin that moves the JDK without moving the digest is still caught.
    #[test]
    fn a_slot_made_for_another_jdk_is_recycled() {
        let s = spec("s1");
        let mut f = mine(&s);
        f.jdk = "21".to_string();

        match decide(&[f], &s, &policy(), NOW, &alive).expect("a decision") {
            Decision::Recycle { reason, .. } => {
                assert!(reason.contains("JDK"), "the reason names the JDK: {reason}");
            }
            other => panic!("a different JDK must recycle the slot, got {other:?}"),
        }
    }

    #[test]
    fn a_slot_idle_past_the_window_is_recycled_before_it_is_reused() {
        let s = spec("s1");
        let mut f = mine(&s);
        f.last_use = Some(NOW - 601);

        match decide(&[f], &s, &policy(), NOW, &alive).expect("a decision") {
            Decision::Recycle { reason, .. } => {
                assert!(reason.contains("idle"), "the reason says idle: {reason}");
            }
            other => panic!("an idle slot must be recycled, got {other:?}"),
        }
    }

    #[test]
    fn idle_is_exactly_the_window_and_never_assumed_when_undatable() {
        assert!(!idle_expired(Some(NOW), NOW, IDLE_KILL), "just used");
        assert!(
            !idle_expired(Some(NOW - 599), NOW, IDLE_KILL),
            "one second inside the window"
        );
        assert!(
            idle_expired(Some(NOW - 600), NOW, IDLE_KILL),
            "exactly the window is idle"
        );
        assert!(
            !idle_expired(None, NOW, IDLE_KILL),
            "a slot we cannot date is not idle: the cold-fill prewarm legitimately runs past the window"
        );
        assert!(
            !idle_expired(Some(NOW + 60), NOW, IDLE_KILL),
            "a marker from the future is a clock problem, not idleness"
        );
    }

    #[test]
    fn the_idle_kill_skips_a_slot_with_a_build_in_flight() {
        let s = spec("s1");
        let mut idle = mine(&s);
        idle.slot_id = "id-idle".to_string();
        idle.last_use = Some(NOW - 3600);
        let mut busy = idle.clone();
        busy.slot_id = "id-busy".to_string();
        let mut stopped = idle.clone();
        stopped.slot_id = "id-stopped".to_string();
        stopped.running = false;

        let facts = vec![idle, busy, stopped];
        let victims = idle_victims(&facts, &policy(), NOW, &|f: &SlotFacts| {
            f.slot_id == "id-busy"
        });
        assert_eq!(
            victims
                .iter()
                .map(|f| f.slot_id.as_str())
                .collect::<Vec<_>>(),
            vec!["id-idle"],
            "only the running slot without a build in flight may be reaped"
        );
    }

    /// The sweep is the one place a foreign slot may be removed, so its filter is the whole
    /// safety argument: dead owner only.
    #[test]
    fn the_sweep_selects_only_slots_whose_owner_is_gone() {
        let s = spec("s1");
        let mut orphan = mine(&s);
        orphan.session = "dead-session".to_string();
        orphan.name = "saife-runner-dead-session".to_string();
        orphan.owner_pid = 4001;
        let live = foreign("live-session", true);

        let facts = vec![orphan, live];
        let victims = orphan_victims(&facts, &|pid: u32, _created: i64| pid == 8120);
        assert_eq!(
            victims
                .iter()
                .map(|f| f.session.as_str())
                .collect::<Vec<_>>(),
            vec!["dead-session"],
            "a live owner's slot must never be swept"
        );
    }

    /// A slot without an owner label (an older build, or a container made by hand) is not
    /// owned by anybody, so it is an orphan by definition.
    #[test]
    fn an_unowned_slot_is_an_orphan() {
        let mut f = foreign("handmade", true);
        f.owner_pid = 0;
        f.owner_created = 0;
        let facts = [f];
        let victims = orphan_victims(&facts, &owner_is_alive);
        assert_eq!(victims.len(), 1, "an unlabelled slot is swept");
    }

    /// The ownership rule, positively: the same session name held by a live owner is refused
    /// rather than adopted - adopting it means two supervisors driving one container.
    #[test]
    fn a_session_name_held_by_a_live_owner_is_refused() {
        let s = spec("s1");
        let mut f = mine(&s);
        f.owner_pid = 999;
        f.owner_created = 5;

        let err = decide(&[f], &s, &policy(), NOW, &alive).expect_err("a refusal");
        let msg = format!("{err:#}");
        assert!(msg.contains("runner_slot_owned_elsewhere"), "got: {msg}");
    }

    /// ... and when that owner is gone the slot is this session's again, not a stranger's.
    #[test]
    fn a_session_name_held_by_a_dead_owner_is_recycled() {
        let s = spec("s1");
        let mut f = mine(&s);
        f.owner_pid = 999;
        f.owner_created = 5;

        match decide(&[f], &s, &policy(), NOW, &dead).expect("a decision") {
            Decision::Recycle { reason, .. } => {
                assert!(reason.contains("owner"), "the reason says why: {reason}")
            }
            other => panic!("a dead owner's slot is replaced, got {other:?}"),
        }
    }

    /// A *name* collision with another session is the same refusal: create would 409, and
    /// retrying around a 409 would silently build in whatever container (or nothing).
    #[test]
    fn another_sessions_slot_with_my_name_is_refused_while_its_owner_lives() {
        let s = spec("s1");
        let mut theirs = foreign("other", true);
        theirs.name = s.name.clone();

        let err = decide(&[theirs], &s, &policy(), NOW, &alive).expect_err("a refusal");
        assert!(
            format!("{err:#}").contains("runner_slot_owned_elsewhere"),
            "got: {err:#}"
        );
    }

    #[test]
    fn another_sessions_slot_is_never_mine() {
        let s = spec("s1");
        let facts = vec![foreign("other", true)];
        assert_eq!(
            decide(&facts, &s, &policy(), NOW, &alive).expect("a decision"),
            Decision::Create,
            "no slot of my session exists, and the other session's is untouched"
        );
        assert_eq!(s.session, "s1", "the spec is what names the session");
    }

    #[test]
    fn creating_is_refused_past_the_cap_and_the_refusal_says_the_number() {
        let s = spec("s1");
        let mut p = policy();
        p.cap = 2;
        let facts = vec![foreign("a", true), foreign("b", true)];

        let err = decide(&facts, &s, &p, NOW, &alive).expect_err("a refusal");
        let msg = format!("{err:#}");
        assert!(msg.contains("runner_slot_cap_reached"), "got: {msg}");
        assert!(msg.contains('2'), "the cap is named: {msg}");
    }

    /// The cap is about the daemons that are running now; a stopped container is not one.
    #[test]
    fn a_stopped_slot_does_not_count_against_the_cap() {
        let s = spec("s1");
        let mut p = policy();
        p.cap = 2;
        let facts = vec![foreign("a", false), foreign("b", false)];
        assert_eq!(
            decide(&facts, &s, &p, NOW, &alive).expect("a decision"),
            Decision::Create
        );
    }

    /// Recycling frees the slot it replaces, so a full engine is not a refusal when the slot
    /// being replaced is one of the full ones.
    #[test]
    fn a_recycled_slot_does_not_count_against_the_cap() {
        let s = spec("s1");
        let mut p = policy();
        p.cap = 2;
        let mut stale = mine(&s);
        stale.image = format!("eclipse-temurin@sha256:{}", "1".repeat(64));
        let facts = vec![stale, foreign("a", true)];

        match decide(&facts, &s, &p, NOW, &alive).expect("a decision") {
            Decision::Recycle { .. } => {}
            other => panic!("the stale slot is recycled before the cap matters: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Live (`-- --ignored`): the same rules against the real engine.
    // -----------------------------------------------------------------------

    use crate::runner::docker::Endpoint;

    /// One live leg at a time: every leg may create slots, and the cap leg counts what is
    /// running on the machine, so two legs in parallel would see each other's containers.
    static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Live {
        engine: Engine,
        /// Removes every slot of every session the leg used, on panic as well.
        _cleanup: Cleanup,
        _serialised: std::sync::MutexGuard<'static, ()>,
    }

    struct Cleanup {
        engine: Engine,
        sessions: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for session in &self.sessions {
                let _ = release(&self.engine, session);
            }
        }
    }

    fn live(sessions: &[String]) -> Live {
        let guard = LIVE.lock().unwrap_or_else(|e| e.into_inner());
        let engine = Engine::connect(Endpoint::resolve().expect("a docker endpoint"));
        Live {
            _cleanup: Cleanup {
                engine: engine.clone(),
                sessions: sessions.to_vec(),
            },
            engine,
            _serialised: guard,
        }
    }

    fn session(tag: &str) -> String {
        format!("{tag}{}", std::process::id())
    }

    /// LIVE: the second build of a session finds its slot instead of making one. The whole
    /// point of the long-lived shape (measured: 1.67 s warm against 4.95-13.6 s cold).
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_session_keeps_one_slot_across_builds() {
        let s = session("oneslot");
        let l = live(std::slice::from_ref(&s));
        let spec = SlotSpec::new(&s);

        let first = admit(&l.engine, &policy(), &spec).expect("admit the first");
        let second = admit(&l.engine, &policy(), &spec).expect("admit the second");
        assert_eq!(
            first.slot.id, second.slot.id,
            "the same container is reused"
        );
        assert!(
            second.recycle_reason.is_none(),
            "nothing was stale, so nothing was recycled: {:?}",
            second.recycle_reason
        );

        let mine = facts_for_status(&l.engine)
            .expect("facts")
            .into_iter()
            .filter(|f| f.session == s)
            .collect::<Vec<_>>();
        assert_eq!(mine.len(), 1, "one slot per session: {mine:?}");
        assert!(mine[0].running, "and it is running");
    }

    /// LIVE: fails (with the same rules) when a slot's recorded JDK is not the pinned one -
    /// the container is replaced, not adopted.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_jdk_change_replaces_the_running_slot() {
        let s = session("jdk");
        let l = live(std::slice::from_ref(&s));

        let first = admit(&l.engine, &policy(), &SlotSpec::new(&s)).expect("admit");
        let mut changed = SlotSpec::new(&s);
        changed.jdk = "21".to_string();
        let second = admit(&l.engine, &policy(), &changed).expect("admit the recycled");

        assert_ne!(first.slot.id, second.slot.id, "the old container is gone");
        let reason = second.recycle_reason.unwrap_or_default();
        assert!(reason.contains("JDK"), "the recycle says why: {reason}");

        let mine = facts_for_status(&l.engine)
            .expect("facts")
            .into_iter()
            .filter(|f| f.session == s)
            .collect::<Vec<_>>();
        assert_eq!(mine.len(), 1, "the stale one did not survive: {mine:?}");
        assert_eq!(mine[0].slot_id, second.slot.id);
    }

    /// LIVE: the idle kill, on the real engine, with the window shortened to a second. Both
    /// directions are asserted: a fresh slot survives, the same slot after the window does not.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_an_idle_slot_is_stopped_and_removed_but_a_fresh_one_survives() {
        let s = session("idle");
        let l = live(std::slice::from_ref(&s));
        let spec = SlotSpec::new(&s);
        let admitted = admit(&l.engine, &policy(), &spec).expect("admit");

        let mut short = policy();
        short.idle = Duration::from_secs(1);
        let nobody_busy = |_: &SlotFacts| false;

        // Freshly touched: nothing to reap.
        let killed =
            kill_idle(&l.engine, &short, Some(&s), now_unix(), &nobody_busy).expect("reap");
        assert!(
            killed.is_empty(),
            "a slot just used is not idle: {killed:?}"
        );

        std::thread::sleep(Duration::from_millis(1200));
        // Removal only: stopping first would wait out the engine's timeout, because the slot's
        // pid 1 is `sleep` and pid 1 ignores SIGTERM (5.13 s per slot measured). A reap that
        // takes seconds instead of milliseconds is what this asserts against.
        let started = std::time::Instant::now();
        let killed =
            kill_idle(&l.engine, &short, Some(&s), now_unix(), &nobody_busy).expect("reap");
        assert_eq!(killed, vec![spec.name.clone()], "the idle slot is removed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a reap removes the container, it does not stop-and-wait: {:?}",
            started.elapsed()
        );

        let still = facts_for_status(&l.engine).expect("facts");
        assert!(
            !still.iter().any(|f| f.slot_id == admitted.slot.id),
            "and it is gone from the engine: {still:?}"
        );
    }

    /// LIVE: the timer, not just the rule. A watchdog that never fires leaves the 479 MB
    /// daemon behind, which is the whole reason the idle kill exists.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_the_watchdog_reaps_an_idle_slot_and_stops_when_dropped() {
        let s = session("watchdog");
        let l = live(std::slice::from_ref(&s));
        let admitted = admit(&l.engine, &policy(), &SlotSpec::new(&s)).expect("admit");

        let mut short = policy();
        short.idle = Duration::from_millis(500);
        let watchdog = spawn_idle_watchdog(
            l.engine.clone(),
            short,
            s.clone(),
            Duration::from_millis(200),
            Arc::new(|_: &SlotFacts| false),
        )
        .expect("spawn the idle watchdog");

        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let gone = facts_for_status(&l.engine)
                .expect("facts")
                .iter()
                .all(|f| f.slot_id != admitted.slot.id);
            if gone {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the watchdog must reap the idle slot"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // Dropping must join promptly rather than block until the next tick.
        let started = std::time::Instant::now();
        drop(watchdog);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the watchdog stops without waiting out its tick: {:?}",
            started.elapsed()
        );
    }

    /// LIVE: the start-up sweep. A dead owner's slot goes, a live owner's survives - the
    /// second half is the one that matters, because sweeping a live session's slot corrupts
    /// a build in progress.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_the_sweep_removes_a_dead_owners_slot_and_spares_a_live_one() {
        let orphan_session = session("orphan");
        let live_session = session("keepme");
        let l = live(&[orphan_session.clone(), live_session.clone()]);

        // A pid that has run and exited, plus a creation time that is not its own: either
        // half of the guard is enough to prove it is not the live process it is not.
        let mut exited = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn a short-lived process");
        let dead_pid = exited.id();
        let _ = exited.wait();

        let mut dead_spec = SlotSpec::new(&orphan_session);
        dead_spec.owner_pid = dead_pid;
        dead_spec.owner_created = 1;
        let dead_slot = l
            .engine
            .create_slot(&dead_spec)
            .expect("create the orphan slot");

        let mut live_spec = SlotSpec::new(&live_session);
        live_spec.owner_pid = std::process::id();
        live_spec.owner_created = crate::sandbox::dacl_journal::current_process_creation_time();
        let kept = l
            .engine
            .create_slot(&live_spec)
            .expect("create the live slot");

        let swept = sweep(&l.engine, &owner_is_alive).expect("sweep");
        let swept_ids = swept.iter().map(|f| f.slot_id.as_str()).collect::<Vec<_>>();
        assert!(
            swept_ids.contains(&dead_slot.id.as_str()),
            "the orphan is swept: {swept_ids:?}"
        );
        assert!(
            !swept_ids.contains(&kept.id.as_str()),
            "a live owner's slot is never swept: {swept_ids:?}"
        );

        let left = facts_for_status(&l.engine).expect("facts");
        assert!(
            left.iter().any(|f| f.slot_id == kept.id),
            "the live slot is still there: {left:?}"
        );
        l.engine.remove_slot(&kept).expect("remove the live slot");
    }

    /// LIVE: the cap, in the only place it can be proven - the engine. The cap is set relative
    /// to what is already running so another session's slot cannot make this flaky.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_the_cap_refuses_the_slot_after_it() {
        let first = session("cap1");
        let second = session("cap2");
        let third = session("cap3");
        let l = live(&[first.clone(), second.clone(), third.clone()]);

        let running_now = l
            .engine
            .list_slot_facts()
            .expect("facts")
            .iter()
            .filter(|f| f.running)
            .count();
        let mut capped = policy();
        capped.cap = running_now + 2;

        admit(&l.engine, &capped, &SlotSpec::new(&first)).expect("first slot");
        admit(&l.engine, &capped, &SlotSpec::new(&second)).expect("second slot");
        let err = admit(&l.engine, &capped, &SlotSpec::new(&third))
            .expect_err("the third slot is past the cap");
        let msg = format!("{err:#}");
        assert!(msg.contains("runner_slot_cap_reached"), "got: {msg}");
    }

    /// LIVE: kill on end. The session's guard is dropped, the container is gone.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_session_end_removes_its_slot() {
        let s = session("release");
        let l = live(std::slice::from_ref(&s));
        let admitted = admit(&l.engine, &policy(), &SlotSpec::new(&s)).expect("admit");

        let keeper = SlotKeeper::new(l.engine.clone(), &s);
        drop(keeper);

        let left = facts_for_status(&l.engine).expect("facts");
        assert!(
            !left.iter().any(|f| f.slot_id == admitted.slot.id),
            "the slot must not outlive the session: {left:?}"
        );
    }

    /// LIVE: the facts `saife runner status` reports - id, digest, created-at, idle-since,
    /// owner - read from the engine and from the slot's own marker.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_facts_carry_the_id_the_digest_the_times_and_the_owner() {
        let s = session("facts");
        let l = live(std::slice::from_ref(&s));
        let admitted = admit(&l.engine, &policy(), &SlotSpec::new(&s)).expect("admit");

        let facts = facts_for_status(&l.engine).expect("facts");
        let me = facts
            .iter()
            .find(|f| f.slot_id == admitted.slot.id)
            .expect("my slot is in the facts");

        assert_eq!(me.slot_id, admitted.slot.id);
        assert_eq!(me.name, format!("saife-runner-{s}"));
        assert_eq!(me.session, s);
        assert_eq!(
            me.image, RUNNER_IMAGE,
            "the report carries the pinned digest"
        );
        assert!(me.image.contains("@sha256:"), "and it is a digest");
        assert!(me.running);
        assert_eq!(me.owner_pid, std::process::id());
        let age = now_unix() - me.created_at;
        assert!(
            (0..120).contains(&age),
            "created-at is this slot's own creation: {age} s old"
        );
        let idle = me.last_use.expect("the last-use marker is readable");
        assert!(
            (0..120).contains(&(now_unix() - idle)),
            "idle-since is when the slot was used: {idle}"
        );
        eprintln!(
            "live: {} {} created {} idle since {}",
            me.slot_id,
            me.image,
            me.created_iso(),
            me.idle_since_iso().unwrap_or_default()
        );
    }
}
