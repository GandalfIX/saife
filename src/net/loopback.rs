//! Register the AppContainer SID for loopback access.
//!
//! AC-3.15 (per-port loopback scoping) is deferred to F-6 (WFP driver);
//! AppContainer's loopback exemption is all-or-nothing per SID. We grant
//! full loopback here so the sandboxed process can reach the proxy on
//! 127.0.0.1:<proxy-port>. The proxy's X-Sandbox-Token gate (AC-3.12)
//! and the fact that other loopback services don't honor our token
//! provide the practical isolation in the MVP.

use windows::core::*;
use windows::Win32::Security::*;

// NetworkIsolationSetAppContainerConfig lives in
// Win32::NetworkManagement::WindowsFirewall, whose feature gate is not
// enabled in Cargo.toml. We declare the FFI binding directly via the
// `link!` macro so this module stays self-contained (the task constrains
// us to editing only this file). The signature is the windows 0.62
// shape: a count + pointer to a SID_AND_ATTRIBUTES array, returning a
// Win32 error code (ERROR_SUCCESS == 0 on success).
windows::core::link!(
    "api-ms-win-net-isolation-l1-1-0.dll"
    "system"
    fn NetworkIsolationSetAppContainerConfig(
        dwnumpublicappcs: u32,
        appcontainersids: *const SID_AND_ATTRIBUTES,
    ) -> u32
);

/// Register loopback for the AppContainer SID. Best-effort: failures are
/// logged under `SANDBOX_DIAG` but not propagated — direct connects to
/// the proxy would simply fail closed (kernel denies non-exempted
/// loopback), which is a worse failure mode but not a security one.
///
/// We register the SID with no capability attributes, so the process
/// gets loopback access but no internet capability SIDs — direct
/// internet connects fail closed.
pub fn register_loopback(ac_sid: &PSID) -> Result<()> {
    let diag = std::env::var_os("SANDBOX_DIAG").is_some();
    unsafe {
        let sids = [SID_AND_ATTRIBUTES {
            Sid: *ac_sid,
            Attributes: 0,
        }];
        let r = NetworkIsolationSetAppContainerConfig(sids.len() as u32, sids.as_ptr());
        if r != 0 {
            if diag {
                eprintln!("[net] WARN: NetworkIsolationSetAppContainerConfig failed: win32 error {r:#x}");
            }
            return Err(HRESULT::from_win32(r).into());
        }
        if diag {
            eprintln!("[net] loopback exemption registered for AC SID");
        }
    }
    Ok(())
}
