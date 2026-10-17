// WBD D-03/D-04 spike: exercises the documented mxc_sdk::v1 surface
// in-process against the pinned tree. Documented surface only - every API
// used here is in docs/api-reference/rust/v1 at pin 5d7a475a; anything not
// exposed is a recorded blocker downstream, never invented here.

use mxc_sdk::v1::{self, configs, ContainerRequest, Containment, WaitResult};
use serde_json::{json, Value};
use std::io::Write;

fn emit(value: Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
}

fn fmt_err(e: v1::Error) -> String {
    format!("{e}")
}

fn empty_request() -> ContainerRequest {
    ContainerRequest::new("cmd /d /s /c exit 0")
}

fn enumerate_request() -> ContainerRequest {
    let temp = std::env::temp_dir().join("wbd-d03-enumerate-probe");
    // ProcessContainerConfig/ProcessContainerFilesystem are #[non_exhaustive]
    // at the pin: Default + pub-field mutation is the sanctioned out-of-crate
    // construction (struct expressions are E0639 from outside the crate).
    let mut fs = configs::ProcessContainerFilesystem::default();
    fs.enumerate_paths = vec![temp.to_string_lossy().into_owned()];
    let mut cfg = configs::ProcessContainerConfig::default();
    cfg.filesystem = Some(fs);
    ContainerRequest {
        containment: Containment::ProcessContainer(cfg),
        ..empty_request()
    }
}

fn probe_json(out: &v1::ProbeOutput) -> Value {
    let p = &out.probes;
    let ui = &p.ui_capabilities;
    json!({
        "tier": out.tier,
        "needsDaclAugmentation": out.needs_dacl_augmentation,
        "warnings": out.warnings,
        "error": out.error,
        "probes": {
            "baseContainerApiPresent": p.base_container_api_present,
            "nativeCaptureAvailable": p.native_capture_available,
            "guardedCaptureAvailable": p.guarded_capture_available,
            "bfscfgPresent": p.bfscfg_present,
            "bfsCompiledIn": p.bfs_compiled_in,
            "baseContainerSupportsDenyPaths": p.base_container_supports_deny_paths,
            "baseContainerSupportsEnumeratePaths": p.base_container_supports_enumerate_paths,
            "baseContainerSupportsIngressHostLoopbackAllow": p.base_container_supports_ingress_host_loopback_allow,
            "baseContainerSupportsIdentitylessLoopbackProxy": p.base_container_supports_identityless_loopback_proxy,
            "isolationSessionAvailable": p.isolation_session_available,
            "hyperlightAvailable": p.hyperlight_available,
            "uiCapabilities": {
                "canBlockClipboardRead": ui.can_block_clipboard_read,
                "canBlockClipboardWrite": ui.can_block_clipboard_write,
                "canBlockInputInjection": ui.can_block_input_injection,
                "canBlockInputMethodChanges": ui.can_block_input_method_changes,
                "canBlockExternalUiObjects": ui.can_block_external_ui_objects,
                "canBlockGlobalUiNamespace": ui.can_block_global_ui_namespace,
                "canBlockDesktopSwitching": ui.can_block_desktop_switching,
                "canBlockLogoffOrShutdown": ui.can_block_logoff_or_shutdown,
                "canBlockSystemParameterChanges": ui.can_block_system_parameter_changes,
                "canBlockDisplaySettingsChanges": ui.can_block_display_settings_changes,
            },
        },
    })
}

fn scenario_probe() -> Result<Value, String> {
    let host = v1::probe(None).map_err(fmt_err)?;
    let empty = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    let enumerate = v1::probe(Some(&enumerate_request())).map_err(fmt_err)?;
    Ok(json!({
        "host": probe_json(&host),
        "empty": probe_json(&empty),
        "enumerate": probe_json(&enumerate),
    }))
}

fn run_one(command: &str, timeout_ms: Option<u32>) -> Result<Value, String> {
    let started = std::time::Instant::now();
    let request = ContainerRequest {
        timeout_ms,
        ..ContainerRequest::new(command)
    };
    let out = v1::run(request, Default::default()).map_err(fmt_err)?;
    Ok(json!({
        "command": command,
        "timeoutMs": timeout_ms,
        "elapsedMs": started.elapsed().as_millis() as u64,
        "outcome": match out.outcome { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "stdout": String::from_utf8_lossy(&out.stdout),
        "stderr": String::from_utf8_lossy(&out.stderr),
        "warnings": out.warnings,
    }))
}

fn scenario_run_exit() -> Result<Value, String> {
    Ok(json!({
        "exit0": run_one("cmd /d /s /c exit 0", None)?,
        "exit7": run_one("cmd /d /s /c exit 7", None)?,
    }))
}

fn scenario_run_stdio() -> Result<Value, String> {
    Ok(json!({
        "stdout": run_one("cmd /d /s /c echo SDK-STDOUT-MARKER", None)?,
        "stderr": run_one("cmd /d /s /c echo SDK-STDERR-MARKER 1>&2", None)?,
    }))
}

fn scenario_spawn_stdin() -> Result<Value, String> {
    let mut proc = v1::spawn(
        ContainerRequest::new("cmd /d /s /c find /v \"\""),
        Default::default(),
    )
    .map_err(fmt_err)?;
    // take_stdin has take semantics - take ONCE, write through the handle,
    // then drop it before wait_with_output consumes the process.
    let mut stdin = proc.take_stdin();
    let stdin_taken = stdin.is_some();
    if let Some(w) = stdin.as_mut() {
        let _ = w.write_all(b"HELLO-STDIN\r\n");
    }
    drop(stdin);
    let result = proc.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    Ok(json!({
        "stdinTaken": stdin_taken,
        "stdout": stdout,
        "roundTrip": stdout.contains("HELLO-STDIN"),
        "outcome": match result.outcome { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
    }))
}

fn scenario_timeout() -> Result<Value, String> {
    let out = run_one(
        "pwsh -NoProfile -Command Start-Sleep -Seconds 60",
        Some(3_000),
    )?;
    Ok(json!({
        "timeout": out,
        "note": "WaitResult::TimedOut expected; README: timeouts cancel outstanding reads and return partial output",
    }))
}

fn scenario_cancel() -> Result<Value, String> {
    let started = std::time::Instant::now();
    let mut proc = v1::spawn(
        ContainerRequest {
            timeout_ms: None,
            ..ContainerRequest::new(
                "pwsh -NoProfile -Command Start-Sleep -Seconds 120; 'WBD-D03-A4-MARKER'",
            )
        },
        Default::default(),
    )
    .map_err(fmt_err)?;
    let id = proc.id();
    let before_kill = json!({ "tryWait": match proc.try_wait() { Ok(v) => json!(v), Err(e) => json!(format!("{e}")) } });
    proc.kill().map_err(|e| e.to_string())?;
    let wait = proc.wait().map_err(|e| e.to_string())?;
    Ok(json!({
        "pid": id,
        "beforeKill": before_kill,
        "waitAfterKill": match wait { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "elapsedMs": started.elapsed().as_millis() as u64,
    }))
}

fn scenario_force_tier() -> Result<Value, String> {
    let forced = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "appcontainer-dacl".to_string());
    // SAFETY: single-threaded scenario process; the var dies with this process.
    std::env::set_var("MXC_FORCE_TIER", &forced);
    let empty = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    let host = v1::probe(None).map_err(fmt_err)?;
    let tier_empty = empty.tier.map(|s| s.to_string());
    let tier_host = host.tier.map(|s| s.to_string());
    std::env::remove_var("MXC_FORCE_TIER");
    Ok(json!({
        "forcedValue": forced,
        "probeEmpty": probe_json(&empty),
        "probeNone": probe_json(&host),
        "honored": tier_empty.as_deref() == Some(forced.as_str()) || tier_host.as_deref() == Some(forced.as_str()),
        "note": "seam compiled via force-tier-testing feature; an invalid value is silently ignored (real probe chain)",
    }))
}

fn scenario_tier_query() -> Result<Value, String> {
    let backends: Vec<Value> = v1::available_backends()
        .into_iter()
        .map(|b| json!({ "backend": b.backend, "tier": b.tier, "warnings": b.warnings }))
        .collect();
    let mut proc = v1::spawn(
        ContainerRequest::new("cmd /d /s /c exit 3"),
        Default::default(),
    )
    .map_err(fmt_err)?;
    let warnings = proc.warnings();
    let id = proc.id();
    let wait = proc.wait().map_err(|e| e.to_string())?;
    let reprobe = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    Ok(json!({
        "availableBackends": backends,
        "processWarnings": warnings,
        "pid": id,
        "wait": match wait { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "reProbe": probe_json(&reprobe),
        "note": "documented MxcProcess surface exposes warnings/metadata/id/stdio/wait/kill only - no per-process effective-tier accessor (ADR-0002 investigation item); re-probe re-runs request adjudication, not live state",
    }))
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    let result = match scenario.as_str() {
        "probe" => scenario_probe(),
        "run-exit" => scenario_run_exit(),
        "run-stdio" => scenario_run_stdio(),
        "spawn-stdin" => scenario_spawn_stdin(),
        "timeout" => scenario_timeout(),
        "cancel" => scenario_cancel(),
        "force-tier" => scenario_force_tier(),
        "tier-query" => scenario_tier_query(),
        other => Ok(json!({ "scenario": other, "error": "unknown scenario" })),
    };
    match result {
        Ok(value) => emit(json!({ "scenario": scenario, "ok": true, "result": value })),
        Err(e) => emit(json!({ "scenario": scenario, "ok": false, "error": e })),
    }
}
