use anyhow::{Result, bail};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, REG_DWORD, HKEY,
};

/// Minimum supported build: Windows 10 1709 (build 16299) per FR-6.2.
pub const MIN_BUILD: u32 = 16299;

/// Called from `run` before any spawning — fails fast with a clear error if
/// the host is unsupported (AC-1.9).
pub fn check_runtime() -> Result<()> {
    let build = os_build_number()?;
    if build < MIN_BUILD {
        bail!(
            "AppContainer RuleSet requires Windows 10 1709 (build {MIN_BUILD}) or later. \
             Detected build {build}."
        );
    }
    Ok(())
}

/// Called from `setup --check-only`: reports the feature matrix and exits
/// non-zero if any MVP-required capability is missing.
pub fn check(check_only: bool) -> Result<()> {
    if !check_only {
        eprintln!("[sandbox] `setup` without --check-only is not implemented in this slice.");
    }

    let build = os_build_number()?;
    println!("Windows build number      : {build}");
    println!("Minimum supported build   : {MIN_BUILD} (Windows 10 1709)");
    println!(
        "AppContainer + RuleSet     : {}",
        if build >= MIN_BUILD { "available" } else { "MISSING" }
    );
    println!("Job Object                 : available (always, Win9x+)");
    println!("Reverse proxy (network)    : available (US-3)");
    println!("ETW audit                  : not yet implemented in this slice");
    println!("Ed25519 signing key        : not yet implemented in this slice");

    if build < MIN_BUILD {
        bail!("host build {build} is below minimum {MIN_BUILD} (AppContainer RuleSet unavailable)");
    }
    Ok(())
}

/// Read the OS build number from the registry
/// (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild`).
///
/// We use the registry instead of `GetVersionExW` because `GetVersionExW` is
/// subject to manifest-based version lying: an unmanifested binary on
/// Windows 10/11 reports build 9200 (Windows 8) — the manifest-compatible
/// floor. The registry value is not affected by the app manifest and reports
/// the true build. (See PRD AC-1.9.)
fn os_build_number() -> Result<u32> {
    let subkey = windows::core::w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let value = windows::core::w!("CurrentBuild");

    unsafe {
        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, Some(0), KEY_READ, &mut hkey);
        if status.is_err() {
            return Err(anyhow::anyhow!("RegOpenKeyExW failed: 0x{:x}", status.0));
        }

        let mut buf = [0u8; 64];
        let mut len = buf.len() as u32;
        let mut kind = REG_DWORD; // will be overwritten; type hint only.
        let r = RegQueryValueExW(
            hkey,
            value,
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut len),
        );
        let _ = RegCloseKey(hkey);
        if r.is_err() {
            return Err(anyhow::anyhow!("RegQueryValueExW failed: 0x{:x}", r.0));
        }

        let utf16: Vec<u16> = buf[..len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16_lossy(&utf16)
            .trim_end_matches('\0')
            .to_string();
        let build: u32 = s
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("could not parse CurrentBuild `{s}` as u32"))?;
        Ok(build)
    }
}
