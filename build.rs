//! Stamp the Windows resource version into every executable this package builds.
//!
//! `Cargo.toml`'s `[package] version` is the single source of truth (see
//! `docs/design/versioning.md`); this script derives the VERSIONINFO block from it
//! so Explorer's Details tab, Add/Remove Programs and `(Get-Item saife.exe).VersionInfo`
//! all report the number that was actually compiled in, instead of nothing.
//!
//! Two fields carry it, and they answer different questions:
//!
//! * `FileVersion` is four dotted `WORD`s, so a pre-release suffix cannot appear
//!   there: `0.4.0-rc.1` becomes `0.4.0.0`.
//! * `ProductVersion` is a string and keeps the version verbatim, so a release
//!   candidate is distinguishable from the final build in the file's properties.
//!
//! A host without the Windows SDK (`rc.exe`) still builds: the failure is reported
//! as a warning, because every developer does not need a resource block. The
//! release script is what refuses to publish an exe whose `FileVersion` is empty
//! or disagrees with `Cargo.toml`.
//!
//! There are no unit tests here on purpose: cargo does not compile a build script's
//! `#[cfg(test)]` module into any test target, so a test in this file would be dead
//! code that looks like coverage. The assertion lives in `packaging/release.ps1`,
//! which reads the version back out of the built exe.


use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    let version = env::var("CARGO_PKG_VERSION")
        .expect("CARGO_PKG_VERSION is set by cargo for every build script");
    let file_version = match resource_version(&version) {
        Ok(v) => v,
        Err(e) => {
            println!("cargo:warning=no Windows resource version: {e}");
            return;
        }
    };

    let mut res = winresource::WindowsResource::new();
    res.set("FileDescription", "SAIFE Sandbox supervisor")
        .set("ProductName", "SAIFE Sandbox")
        .set("CompanyName", "GandalfIX")
        .set("LegalCopyright", "Copyright (c) 2026 GandalfIX")
        .set("FileVersion", &file_version)
        .set("ProductVersion", &version);

    if let Err(e) = res.compile() {
        println!("cargo:warning=Windows resource not embedded: {e}");
    }
}

/// Turn a semver into the `a.b.c.d` form a Windows resource version needs.
///
/// The numeric core keeps at most four components (missing ones are zero), and a
/// pre-release or build suffix (`-rc.1`, `+sha`) is dropped because the field is
/// numeric-only. A component that is not a `u16` is refused: silently clamping it
/// would ship a version that disagrees with `Cargo.toml`.
fn resource_version(version: &str) -> Result<String, String> {
    let core = version
        .split(['-', '+'])
        .next()
        .ok_or_else(|| format!("empty version {version:?}"))?;
    let mut parts = Vec::new();
    for part in core.split('.') {
        let n: u16 = part
            .parse()
            .map_err(|_| format!("{part:?} in {version:?} is not a 16-bit number"))?;
        parts.push(n);
    }
    while parts.len() < 4 {
        parts.push(0);
    }
    if parts.len() > 4 {
        return Err(format!("{version:?} has more than four components"));
    }
    Ok(parts
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("."))
}
