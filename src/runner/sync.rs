//! Syncing a project into the runner's volume, and the outputs back out.
//!
//! Measured (`docs/research/build-runner/measurements.md` §3): a Windows bind mount costs
//! 2.65 ms per file, a volume 0.038 ms, and a tar round trip of 20 000 files 2.8 s. So the
//! project is copied, not mounted - which makes these two functions the hot path of every
//! build, and makes their semantics (what is copied, what is dropped) part of the feature.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Pack a directory into a tar archive, paths relative to `root`.
///
/// Skips the build directories and `.git` inside the tree only when asked: a caller syncing
/// inputs wants `build/` gone (it is the output), while a caller syncing a cache wants it.
pub fn pack_dir(root: &Path, skip: &[&str]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    walk(&mut builder, root, Path::new(""), skip)?;
    builder.into_inner().context("runner: finish the tar")
}

/// Pack exactly the entries `paths` names, relative to `root`; a directory entry brings its
/// whole subtree.
///
/// The list is CLOSED on purpose. It is what the container sees, and nothing is added on the
/// caller's behalf: a Gradle build whose `settings.gradle.kts` or composite (`includeBuild`)
/// root is not named fails at configuration time - visibly - rather than the runner guessing
/// which extra files a build "must have needed" and producing a copy nobody can predict from
/// the list it was given.
///
/// The skip list applies here exactly as it does in a whole-project copy, entry names
/// included, so an allow-list cannot smuggle a stale `build/` into the container.
pub fn pack_paths(root: &Path, paths: &[String], skip: &[&str]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in paths {
        // `.` names the project itself, and `./apps/x` is the entry `apps/x`.
        let rel: PathBuf = Path::new(entry)
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        if rel.as_os_str().is_empty() {
            walk(&mut builder, root, Path::new(""), skip)?;
            continue;
        }
        if rel
            .file_name()
            .map(|name| skip.iter().any(|s| name.to_string_lossy() == *s))
            .unwrap_or(false)
        {
            continue;
        }
        let source = root.join(&rel);
        // H1 residual (verdict: H1 itself WRONG, this residual is real): the old
        // `std::fs::metadata` FOLLOWS a link, so a listed symlink had its TARGET
        // classified - a symlink-to-file was read and packed, a symlink-to-dir was
        // walked into. The refusal is on the entry itself, before anything is read.
        let meta = std::fs::symlink_metadata(&source)
            .with_context(|| format!("runner: inspect {}", source.display()))?;
        if super::is_reparse_point(&meta) {
            bail!(
                "runner: {} is a reparse point (a link or junction); the copy allow-list \
                 names real paths only - remove it or name the real path instead",
                source.display()
            );
        }
        if meta.is_dir() {
            builder
                .append_dir(&rel, &source)
                .with_context(|| format!("runner: pack {}", source.display()))?;
            walk(&mut builder, &source, &rel, skip)?;
        } else {
            append_file(&mut builder, &source, &rel)?;
        }
    }
    builder.into_inner().context("runner: finish the tar")
}

/// One file into the archive, with the mode every packed file gets.
///
/// Callers must already have refused reparse points (H1 residual): [`pack_paths`]
/// checks its listed entries and [`walk`] checks every directory entry, so a
/// reparse point never reaches this function. `File::open` would FOLLOW a
/// symlink-to-file (there is no `OPEN_REPARSE_POINT` here), which is exactly the
/// behaviour the two call-site checks exist to prevent.
fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &Path, rel: &Path) -> Result<()> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("runner: open {}", path.display()))?;
    // Mode is explicit on purpose. Windows has no executable bit, so the metadata
    // the tar crate reads produces an entry without one - and the first real build
    // failed with `exec: "./gradlew": permission denied` (exit 126) because of it.
    // 0o755 for every file is what git-on-Windows effectively does (core.fileMode
    // is false there), and inside a throwaway container it costs nothing.
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&file.metadata()?);
    header.set_mode(0o755);
    header.set_size(file.metadata()?.len());
    header.set_cksum();
    builder
        .append_data(&mut header, rel, &mut file)
        .with_context(|| format!("runner: pack {}", path.display()))?;
    Ok(())
}

/// Depth-first, applying `skip` to **every** directory, not just the root.
///
/// Measured on a real project with a composite build: `sample-gradle/build-logic/build/classes`
/// and `build-logic/.gradle/**` were copied in, 645 files / 4.1 MB where the sources are 26 files
/// / 304 KB. Two wrongs at once - the container starts from the host's stale compiled output, so
/// "a build sees a snapshot of the sources" was false for every subproject, and every copy was
/// fourteen times larger than it needed to be.
fn walk(builder: &mut tar::Builder<Vec<u8>>, root: &Path, rel: &Path, skip: &[&str]) -> Result<()> {
    for entry in
        std::fs::read_dir(root).with_context(|| format!("runner: read {}", root.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if skip.iter().any(|s| name.to_string_lossy() == *s) {
            continue;
        }
        let path = entry.path();
        let rel_path = rel.join(&name);
        // H1 residual (verdict: H1 itself WRONG, the refusal is still right): a
        // junction inside the project used to reach `append_file` and fail there
        // with an opaque ERROR_ACCESS_DENIED from `File::open` - the pack failed,
        // but said nothing about WHY. A symlink-to-FILE was worse: it was followed
        // and its target's contents were packed. One named refusal covers both
        // shapes, `symlink_metadata` so the link itself is inspected, not the
        // target it names.
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("runner: inspect {}", path.display()))?;
        if super::is_reparse_point(&meta) {
            bail!(
                "runner: {} is a reparse point (a link or junction); a build packs real \
                 project files only - remove it or name the real path instead",
                path.display()
            );
        }
        if meta.is_dir() {
            builder
                .append_dir(&rel_path, &path)
                .with_context(|| format!("runner: pack {}", path.display()))?;
            walk(builder, &path, &rel_path, skip)?;
        } else {
            append_file(builder, &path, &rel_path)?;
        }
    }
    Ok(())
}

/// Unpack an archive into `dest`, keeping only entries `keep` accepts.
///
/// Returns how many entries were written. The filter is what makes "declared outputs only"
/// true: syncing a whole tree back would overwrite the agent's edits with snapshot content.
#[allow(dead_code)] // the production path always knows whether to strip; the tests use both
pub fn unpack_into(tar: &[u8], dest: &Path, keep: &dyn Fn(&Path) -> bool) -> Result<usize> {
    unpack_filtered(tar, dest, false, &|p, _| keep(p))
}

/// The same, with the option to drop the archive's first path component.
///
/// The engine's `/archive` answers are relative to the **parent** of the requested path, so
/// `GET …?path=/src/out` yields `out/art.txt`. Sync-out strips that component; sync-in does
/// not, because `pack_dir` already produces paths relative to the project root.
#[allow(dead_code)] // used by the engine round-trip test and the sync tests; the guarded
// production sync-out path uses `unpack_into_at_typed` for its kind-aware keeper
pub fn unpack_into_at(
    tar: &[u8],
    dest: &Path,
    strip_top: bool,
    keep: &dyn Fn(&Path) -> bool,
) -> Result<usize> {
    unpack_filtered(tar, dest, strip_top, &|p, _| keep(p))
}

/// `unpack_into_at` with a type-aware keeper: the closure sees each entry's
/// [`tar::EntryType`] as well as its path, so sync-out can refuse a link entry by
/// KIND rather than by name. C2: the path-based keeper above stays as it is for
/// the engine's own round-trip (`docker.rs`); this is the one the guarded
/// sync-out path uses.
pub fn unpack_into_at_typed(
    tar: &[u8],
    dest: &Path,
    strip_top: bool,
    keep: &dyn Fn(&Path, tar::EntryType) -> bool,
) -> Result<usize> {
    unpack_filtered(tar, dest, strip_top, keep)
}

/// The shared unpack loop behind the three wrappers above.
fn unpack_filtered(
    tar: &[u8],
    dest: &Path,
    strip_top: bool,
    keep: &dyn Fn(&Path, tar::EntryType) -> bool,
) -> Result<usize> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar));
    let mut written = 0usize;
    for entry in archive.entries().context("runner: read the tar")? {
        let mut entry = entry.context("runner: read a tar entry")?;
        let path = entry
            .path()
            .context("runner: read an entry path")?
            .to_path_buf();
        let kind = entry.header().entry_type();
        // Paths are packed relative to the root, so they are already what belongs under
        // `dest` - but an archive is untrusted input, so absolute paths, `..` and Windows
        // prefixes are dropped rather than joined (tar-slip).
        let relative: PathBuf = if strip_top {
            path.components().skip(1).collect()
        } else {
            path.components().collect()
        };
        let escapes = relative.is_absolute()
            || relative.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            });
        if escapes || relative.as_os_str().is_empty() || !keep(&relative, kind) {
            continue;
        }
        let target = dest.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("runner: create {}", parent.display()))?;
        }
        entry
            .unpack(&target)
            .with_context(|| format!("runner: write {}", target.display()))?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saife-sync-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_tree_round_trips_and_the_skip_list_is_honoured() {
        let src = scratch("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("hello.txt"), b"hi").unwrap();
        std::fs::write(src.join("sub/deep.txt"), b"deep").unwrap();
        std::fs::create_dir_all(src.join("build")).unwrap();
        std::fs::write(src.join("build/stale.class"), b"x").unwrap();

        let tar = pack_dir(&src, &["build"]).expect("pack");
        let dest = scratch("dest");
        let n = unpack_into(&tar, &dest, &|_| true).expect("unpack");
        assert!(n >= 3, "directory entries plus files, got {n}");
        assert_eq!(std::fs::read(dest.join("hello.txt")).unwrap(), b"hi");
        assert_eq!(std::fs::read(dest.join("sub/deep.txt")).unwrap(), b"deep");
        assert!(
            !dest.join("build/stale.class").exists(),
            "the skip list must keep outputs out of the input tree"
        );
    }

    /// The executable bit has to survive packing: without it a `gradlew` arrives in the
    /// container unexecutable (measured as exit 126 on the first real build).
    #[test]
    fn packed_files_carry_the_executable_bit() {
        let src = scratch("mode");
        std::fs::write(src.join("gradlew"), b"#!/bin/sh\n").unwrap();
        let tar = pack_dir(&src, &[]).expect("pack");

        let mut archive = tar::Archive::new(std::io::Cursor::new(tar));
        let entry = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.path()
                    .map(|p| p.to_string_lossy().ends_with("gradlew"))
                    .unwrap_or(false)
            })
            .expect("the gradlew entry");
        let mode = entry.header().mode().expect("a mode");
        assert_eq!(mode & 0o111, 0o111, "mode was {mode:o}");
    }

    #[test]
    fn the_filter_decides_what_lands_on_the_host() {
        let src = scratch("src2");
        std::fs::create_dir_all(src.join("out")).unwrap();
        std::fs::write(src.join("out/keep.jar"), b"jar").unwrap();
        std::fs::write(src.join("out/log.txt"), b"log").unwrap();
        let tar = pack_dir(&src, &[]).expect("pack");

        let dest = scratch("dest2");
        let n = unpack_into(&tar, &dest, &|p| {
            p.extension().map(|e| e == "jar").unwrap_or(false)
        })
        .expect("unpack");
        assert_eq!(n, 1, "only the jar");
        assert!(dest.join("out/keep.jar").exists());
        assert!(!dest.join("out/log.txt").exists());
    }
    fn names(tar: &[u8]) -> Vec<String> {
        tar::Archive::new(std::io::Cursor::new(tar))
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().replace('\\', "/"))
            .collect()
    }

    /// The allow-list IS the copy: the root build script and one app travel, the other app
    /// and the root script do not. This is the "several Gradle projects in one repo" case
    /// the feature exists for, and the closed-set caveat: `settings.gradle.kts` has to be
    /// named explicitly, because it is what `includeBuild`/`include` resolves through.
    #[test]
    fn a_request_that_names_its_paths_copies_only_those() {
        let root = scratch("paths");
        std::fs::create_dir_all(root.join("apps/payments/src")).unwrap();
        std::fs::write(root.join("apps/payments/src/Pay.java"), b"class Pay {}").unwrap();
        std::fs::create_dir_all(root.join("apps/checkout/src")).unwrap();
        std::fs::write(root.join("apps/checkout/src/Cart.java"), b"class Cart {}").unwrap();
        std::fs::write(root.join("settings.gradle.kts"), b"rootProject.name").unwrap();
        std::fs::write(root.join("build.gradle.kts"), b"plugins {}").unwrap();

        let tar = pack_paths(
            &root,
            &[
                "apps/payments".to_string(),
                "settings.gradle.kts".to_string(),
            ],
            &["build", ".gradle", ".git"],
        )
        .expect("pack");
        let names = names(&tar);
        assert!(
            names.iter().any(|n| n == "apps/payments/src/Pay.java"),
            "the named directory's subtree must travel: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "settings.gradle.kts"),
            "the named file must travel: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("checkout")),
            "an app nobody named must not travel: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "build.gradle.kts"),
            "an unnamed root file must not travel: {names:?}"
        );
    }

    /// The skip list is a boundary, not a preference an allow-list can override: naming a
    /// directory copies its sources, not its previous build.
    #[test]
    fn the_skip_list_still_applies_inside_a_listed_directory() {
        let root = scratch("paths-skip");
        std::fs::create_dir_all(root.join("apps/payments/src")).unwrap();
        std::fs::write(root.join("apps/payments/src/Pay.java"), b"class Pay {}").unwrap();
        std::fs::create_dir_all(root.join("apps/payments/build/classes")).unwrap();
        std::fs::write(root.join("apps/payments/build/classes/Pay.class"), b"junk").unwrap();
        std::fs::create_dir_all(root.join("apps/payments/.gradle/9.8.2")).unwrap();
        std::fs::write(root.join("apps/payments/.gradle/9.8.2/state.bin"), b"junk").unwrap();

        let tar = pack_paths(
            &root,
            &["apps/payments".to_string()],
            &["build", ".gradle", ".git"],
        )
        .expect("pack");
        let entries = names(&tar);
        assert!(
            entries.iter().any(|n| n == "apps/payments/src/Pay.java"),
            "{entries:?}"
        );
        assert!(
            !entries
                .iter()
                .any(|n| n.contains("/build/") || n.contains("/.gradle/")),
            "outputs and caches must not travel: {entries:?}"
        );

        let direct = pack_paths(
            &root,
            &["apps/payments/build".to_string()],
            &["build", ".gradle", ".git"],
        )
        .expect("pack");
        assert!(
            names(&direct).is_empty(),
            "an entry that names a skipped directory copies nothing: {:?}",
            names(&direct)
        );
    }

    /// `"."` is the whole project, spelled as a profile default can spell it. It must not
    /// become a `./`-prefixed tar the container unpacks into a subdirectory of `/src`.
    #[test]
    fn a_dot_entry_is_the_whole_project() {
        let root = scratch("paths-dot");
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::create_dir_all(root.join("build")).unwrap();
        std::fs::write(root.join("build/out.txt"), b"out").unwrap();

        let tar = pack_paths(&root, &[".".to_string()], &["build"]).expect("pack");
        assert_eq!(
            names(&tar),
            vec!["a.txt".to_string()],
            "`.` is the project root, with the skip list still applied"
        );
    }

    /// MEASUREMENT (`cargo test -- --ignored --nocapture twenty_thousand`): the number that
    /// decides whether a monorepo copy needs a different strategy. Writes ~20 000 small files,
    /// times a whole-tree pack against a 10 % allow-list, and removes the tree on the way out -
    /// on a panic too, because a leftover 20 k-file tree is the one thing this must not do.
    #[test]
    #[ignore = "measurement: writes ~20 000 files into the temp dir; run with -- --ignored --nocapture"]
    fn a_twenty_thousand_file_tree_packs_in_seconds_not_minutes() {
        struct Tree(PathBuf);
        impl Drop for Tree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let root = scratch("measure-tree");
        let _tree = Tree(root.clone());
        const FILES: usize = 20_000;
        const DIRS: usize = 200;
        for d in 0..DIRS {
            let dir = root.join(format!("libs/mod{d:03}/src"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..FILES / DIRS {
                std::fs::write(dir.join(format!("F{f:03}.java")), vec![b'x'; 1024]).unwrap();
            }
        }
        let subset: Vec<String> = (0..DIRS / 10).map(|d| format!("libs/mod{d:03}")).collect();

        let started = std::time::Instant::now();
        let all = pack_dir(&root, &["build", ".gradle", ".git"]).expect("pack everything");
        let whole = started.elapsed();

        let started = std::time::Instant::now();
        let some =
            pack_paths(&root, &subset, &["build", ".gradle", ".git"]).expect("pack the subset");
        let part = started.elapsed();

        eprintln!(
            "measure: {FILES} files, whole tree {whole:?} ({} bytes) | 10% allow-list {part:?} ({} bytes)",
            all.len(),
            some.len()
        );
        assert!(
            some.len() * 5 < all.len(),
            "the 10% subset must be a fraction of the archive: {} vs {}",
            some.len(),
            all.len()
        );
    }

    /// H1 (verdict: WRONG — pin the corrected behavior): a project containing a
    /// junction to an outside directory must NOT have the junction target's
    /// contents in the packed tar. `walk` recurses on `FileType::is_dir()`, which
    /// is false for a junction (it classifies as a symlink), so the junction is
    /// not recursed into and the pack fails cleanly instead of exfiltrating.
    /// See docs/design/2026-11-09-security-review-verdicts.md §H1.
    #[cfg(windows)]
    #[test]
    fn a_junction_inside_the_project_is_not_packed_into_the_tar() {
        struct Guard(PathBuf);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let root = scratch("h1-junction");
        let _root_guard = Guard(root.clone());
        std::fs::write(root.join("real.txt"), b"kept").unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-sync-h1-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        let _outside_guard = Guard(outside.clone());
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"exfil").unwrap();

        let link = root.join("linked");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction must be created for this test"
        );

        // Either the pack fails cleanly (the observed behavior: `File::open` on a
        // junction is ACCESS_DENIED) or it succeeds without the target's contents.
        match pack_dir(&root, &[]) {
            Ok(tar) => {
                let names = names(&tar);
                assert!(
                    !names.iter().any(|n| n.contains("secret")),
                    "the junction target's contents must never be in the tar: {names:?}"
                );
            }
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    !msg.contains("secret"),
                    "a pack failure must not carry the target's contents: {msg}"
                );
            }
        }
    }

    /// A composite build has its own `build/` and `.gradle/` one level down. Skipping only the
    /// root copied 4.1 MB where 304 KB of sources exist, and made "the build sees a snapshot
    /// of the sources" false for every subproject.
    #[test]
    fn nested_outputs_and_caches_are_skipped_too() {
        let root = scratch("nested");
        std::fs::create_dir_all(root.join("src/main/java")).unwrap();
        std::fs::write(root.join("src/main/java/A.java"), b"class A {}").unwrap();
        std::fs::create_dir_all(root.join("build-logic/build/classes")).unwrap();
        std::fs::write(root.join("build-logic/build/classes/A.class"), b"junk").unwrap();
        std::fs::create_dir_all(root.join("build-logic/.gradle/9.8.2")).unwrap();
        std::fs::write(root.join("build-logic/.gradle/9.8.2/state.bin"), b"junk").unwrap();
        std::fs::create_dir_all(root.join("build")).unwrap();
        std::fs::write(root.join("build/root.class"), b"junk").unwrap();

        let tar = pack_dir(&root, &["build", ".gradle", ".git"]).expect("pack");
        let names: Vec<String> = tar::Archive::new(std::io::Cursor::new(tar))
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(
            names.iter().any(|n| n.ends_with("src/main/java/A.java")),
            "{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("/build/")
                || n.contains("/.gradle/")
                || n.starts_with("build/")),
            "nested outputs must not travel: {names:?}"
        );
    }

    // ---- H1 residual: reparse points are refused BY NAME --------------------

    /// Removes a scratch tree on the way out, including on a panic: a test that
    /// creates links must not leave them behind for the next run to trip over.
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            // `remove_dir_all` removes a junction without recursing into its
            // target on Windows (it detects the reparse point), and a symlink
            // with `remove_file`, so this is safe against the links below.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// H1 residual (verdict: H1 itself was WRONG - `is_dir()` is false for a
    /// junction, so it was never recursed into). What remained was the failure
    /// MODE: the junction reached `append_file`, whose `File::open` failed with
    /// an opaque ERROR_ACCESS_DENIED, so the build never started and the refusal
    /// said nothing about why. It must be a NAMED refusal now, and no external
    /// content may travel either way.
    #[cfg(windows)]
    #[test]
    fn a_junction_inside_the_project_is_refused_by_name() {
        let root = scratch("h1-named");
        let _root_guard = Guard(root.clone());
        std::fs::write(root.join("real.txt"), b"kept").unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-sync-h1-named-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        let _outside_guard = Guard(outside.clone());
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"exfil").unwrap();

        let link = root.join("linked");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction must be created for this test"
        );

        let err = pack_dir(&root, &[])
            .expect_err("a junction inside the project must be refused, not packed through");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "the refusal must name a reparse point: {msg}"
        );
        assert!(
            msg.contains("linked"),
            "the refusal must name the offending path: {msg}"
        );
        // Refusal, not partial pack: there is no archive at all, so the
        // junction target's contents cannot have travelled.
        assert!(!msg.contains("exfil"), "no external content: {msg}");
    }

    /// H1 residual: the symlink-to-FILE case was the real exfiltration variant -
    /// `File::open` FOLLOWS such a link (there is no `OPEN_REPARSE_POINT`), so a
    /// `loot -> ~/.ssh/id_rsa` inside the project was packed. Refused now. Needs
    /// symlink-creation privilege (Developer Mode or the token); if the host
    /// denies it, the junction test above still covers the unprivileged vector.
    #[cfg(windows)]
    #[test]
    fn a_symlink_to_a_file_inside_the_project_is_refused_not_followed() {
        let root = scratch("h1-filelink");
        let _root_guard = Guard(root.clone());
        std::fs::write(root.join("real.txt"), b"kept").unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-sync-h1-filelink-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        let _outside_guard = Guard(outside.clone());
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"exfil").unwrap();

        let link = root.join("loot");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink"])
            .arg(&link)
            .arg(outside.join("secret.txt"))
            .status()
            .expect("mklink runs");
        if !status.success() {
            eprintln!(
                "SKIP: this host refuses symlink creation without privilege \
                 (the junction test covers the unprivileged vector)"
            );
            return;
        }

        let err = pack_dir(&root, &[])
            .expect_err("a symlink-to-file inside the project must be refused, not followed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "the refusal must name a reparse point: {msg}"
        );
        assert!(
            msg.contains("loot"),
            "the refusal must name the offending path: {msg}"
        );
        assert!(!msg.contains("exfil"), "no external content: {msg}");
    }

    /// ... and the same refusal for a LISTED entry, which does not go through
    /// `walk`: `pack_paths` used `std::fs::metadata`, which follows the link, so
    /// a listed symlink had its target classified - a symlink-to-file was read
    /// and packed. The allow-list names real paths only.
    #[cfg(windows)]
    #[test]
    fn a_listed_entry_that_is_a_reparse_point_is_refused() {
        let root = scratch("h1-listed");
        let _root_guard = Guard(root.clone());
        std::fs::write(root.join("real.txt"), b"kept").unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-sync-h1-listed-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        let _outside_guard = Guard(outside.clone());
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"exfil").unwrap();

        let link = root.join("loot");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction must be created for this test"
        );

        let err = pack_paths(&root, &["loot".to_string()], &[])
            .expect_err("a listed reparse point must be refused, not followed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "the refusal must name a reparse point: {msg}"
        );
        assert!(msg.contains("loot"), "the refusal names the entry: {msg}");
        assert!(!msg.contains("exfil"), "no external content: {msg}");
    }
}
