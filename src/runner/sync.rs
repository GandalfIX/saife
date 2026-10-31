//! Syncing a project into the runner's volume, and the outputs back out.
//!
//! Measured (`docs/research/build-runner/measurements.md` §3): a Windows bind mount costs
//! 2.65 ms per file, a volume 0.038 ms, and a tar round trip of 20 000 files 2.8 s. So the
//! project is copied, not mounted - which makes these two functions the hot path of every
//! build, and makes their semantics (what is copied, what is dropped) part of the feature.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Pack a directory into a tar archive, paths relative to `root`.
///
/// Skips the build directories and `.git` inside the tree only when asked: a caller syncing
/// inputs wants `build/` gone (it is the output), while a caller syncing a cache wants it.
pub fn pack_dir(root: &Path, skip: &[&str]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in
        std::fs::read_dir(root).with_context(|| format!("runner: read {}", root.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if skip.iter().any(|s| name.to_string_lossy() == *s) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            builder
                .append_dir_all(&name, &path)
                .with_context(|| format!("runner: pack {}", path.display()))?;
        } else {
            let mut file = std::fs::File::open(&path)
                .with_context(|| format!("runner: open {}", path.display()))?;
            builder
                .append_file(&name, &mut file)
                .with_context(|| format!("runner: pack {}", path.display()))?;
        }
    }
    builder.into_inner().context("runner: finish the tar")
}

/// Unpack an archive into `dest`, keeping only entries `keep` accepts.
///
/// Returns how many entries were written. The filter is what makes "declared outputs only"
/// true: syncing a whole tree back would overwrite the agent's edits with snapshot content.
pub fn unpack_into(tar: &[u8], dest: &Path, keep: &dyn Fn(&Path) -> bool) -> Result<usize> {
    unpack_into_at(tar, dest, false, keep)
}

/// The same, with the option to drop the archive's first path component.
///
/// The engine's `/archive` answers are relative to the **parent** of the requested path, so
/// `GET …?path=/src/out` yields `out/art.txt`. Sync-out strips that component; sync-in does
/// not, because `pack_dir` already produces paths relative to the project root.
pub fn unpack_into_at(
    tar: &[u8],
    dest: &Path,
    strip_top: bool,
    keep: &dyn Fn(&Path) -> bool,
) -> Result<usize> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar));
    let mut written = 0usize;
    for entry in archive.entries().context("runner: read the tar")? {
        let mut entry = entry.context("runner: read a tar entry")?;
        let path = entry
            .path()
            .context("runner: read an entry path")?
            .to_path_buf();
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
        if escapes || relative.as_os_str().is_empty() || !keep(&relative) {
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
}
