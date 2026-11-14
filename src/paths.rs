//! The Win32 path-comparison key family: one spelling per path so a deny
//! and a grant compare on the same normalized text. Used by the profile
//! policy layer and by the mxc request builder - it must not depend on a
//! feature-gated module.

/// Normalized comparison key for a Windows path.
///
/// Two spellings that name the same object must compare equal, and none of these
/// paths has to exist — a deny list is configuration, not a directory scan — so
/// nothing here touches the filesystem:
///
/// * separators become `\` and runs of them collapse;
/// * a verbatim/device prefix is dropped: `\\?\C:\x` and `\\.\C:\x` are
///   `C:\x`, and `\\?\UNC\server\share` is `\\server\share`;
/// * each component loses its **trailing** dots and spaces, which Win32 ignores,
///   **before** the `.`/`..` tests — so `.. ` (trailing space) is still the
///   parent directory rather than a segment that trims to nothing;
/// * `.` segments are dropped and `..` segments collapse against their parent,
///   clamping at the root as Windows does;
/// * the UNC root's server and share components lose their trailing dots and
///   spaces too, like every other component: `\\srv\share.\x` is
///   `\\srv\share\x`;
/// * a trailing separator is dropped (a drive root keeps the bare `c:` form, so
///   that it still prefixes its own children) and the whole key is case-folded
///   by [`fold_case`].
///
/// **Spellings this deliberately does *not* unify.** Each of these still compares
/// *different*, so a deny spelled one way does not cover a grant spelled the
/// other — recorded here so the gap is a known caveat rather than a surprise:
///
/// * **8.3 short names**: `C:\PROGRA~1` and `C:\Program Files` are distinct keys
///   (expanding them needs the filesystem);
/// * **junctions and symlinks**: an alias and its target are distinct keys, for
///   the same reason — nothing here touches the disk;
/// * **drive-relative (`C:work`) and root-relative (`\Windows`) spellings**: they
///   resolve against a per-drive or per-process current directory this function
///   cannot know, so they are distinct from the absolute forms. That is why
///   [`filesystem_policy`] and [`build_request`] make their cwd and launcher
///   absolute first ([`absolute_path`]) instead of trusting the caller's
///   spelling;
/// * **alternate data streams**: `C:\x\file:stream` keeps its `:stream` suffix,
///   which is not stripped, so it never matches the base file.
pub(crate) fn path_key(path: &str) -> String {
    let unified = unify_path_prefix(path);
    let (root, rest) = split_path_root(&unified);

    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        // Trailing spaces first, then the `.`/`..` tests, then the dots: Windows
        // ignores a component's trailing dots and spaces *before* deciding what
        // the component means, so `.. ` is the parent directory. Doing it in any
        // other order dropped `.. ` (it trimmed to nothing), keying
        // `C:\work\sub\.. \x` as `c:\work\sub\x`. Dots cannot be trimmed before
        // the `..` test for the same reason in reverse: `..` would lose its own
        // dots.
        let segment = segment.trim_end_matches(' ');
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        let segment = trim_component(segment);
        if !segment.is_empty() {
            segments.push(segment);
        }
    }

    let mut key = fold_case(&root);
    for segment in segments {
        if !key.is_empty() && !key.ends_with('\\') {
            key.push('\\');
        }
        key.push_str(&fold_case(segment));
    }
    key
}
/// Separator unification plus verbatim/device-prefix removal, so
/// [`path_key`]'s segment pass sees one spelling per path.
pub(crate) fn unify_path_prefix(path: &str) -> String {
    let raw = path.trim().replace('/', "\\");
    let bytes = raw.as_bytes();
    if bytes.len() < 4
        || !(bytes[..4].eq_ignore_ascii_case(br"\\?\") || bytes[..4].eq_ignore_ascii_case(br"\\.\"))
    {
        return raw;
    }
    // Byte 4 is a char boundary: the prefix that matched is ASCII.
    let rest = &raw[4..];
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() >= 4 && rest_bytes[..4].eq_ignore_ascii_case(br"UNC\") {
        // `\\?\UNC\server\share` is the plain UNC path `\\server\share`.
        return format!("\\\\{}", &rest[4..]);
    }
    rest.to_string()
}
/// Split a unified path into its root (`C:`, `\\server\share`, `\`, or `""`)
/// and the part below it.
///
/// A drive root is returned **without** its separator so the joined key still
/// prefixes its children (`c:` covers `c:\work`); the join in [`path_key`]
/// re-adds exactly one separator. The UNC root's server and share components are
/// trimmed like every other component ([`trim_component`]), which is why the root
/// is owned: `\\srv\share.` and `\\srv\share` must be one root.
pub(crate) fn split_path_root(path: &str) -> (String, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        // UNC root: `\\server\share`; everything after it is segments.
        let mut parts = path[2..].splitn(3, '\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        let end = 2 + server.len() + usize::from(!share.is_empty()) + share.len();
        let root = if share.is_empty() {
            format!("\\\\{}", trim_component(server))
        } else {
            format!("\\\\{}\\{}", trim_component(server), trim_component(share))
        };
        return (root, &path[end..]);
    }
    if bytes.len() >= 2 && bytes[1] == b':' {
        return (path[..2].to_string(), &path[2..]);
    }
    if bytes.first() == Some(&b'\\') {
        return ("\\".to_string(), &path[1..]);
    }
    (String::new(), path)
}
/// One path component as Win32 compares it: trailing dots and spaces are not part
/// of the name.
pub(crate) fn trim_component(component: &str) -> &str {
    component.trim_end_matches(['.', ' '])
}
/// Win32's case fold, as closely as `std` approximates it: Unicode **uppercase**
/// (`str::to_uppercase`).
///
/// Windows' ordinal case-insensitive compare (`CompareStringOrdinal` with
/// `bIgnoreCase`) uppercases each character from its invariant table, so folding
/// both sides with Unicode uppercase agrees with it across the scripts a Windows
/// path practically contains (ASCII, Latin-1, Greek, Cyrillic) where the previous
/// `to_ascii_lowercase` did not: `C:\Users\Ä` and `C:\Users\ä` name one directory
/// and now produce one key, so a deny of either covers a grant under the other.
/// Folding to uppercase rather than lowercase matters for the same reason:
/// uppercase is what Windows compares.
///
/// **Approximation, recorded not hidden:** `std` performs *full* case mapping,
/// which may expand one character into several (`ß` → `SS`), while Windows maps
/// character for character. Where the two disagree the difference is an
/// *over*-match — two spellings compare equal here that Windows would distinguish
/// — which fails closed: the over-covering deny is refused
/// ([`RequestError::DenyCoversGrant`]) rather than shipped or dropped. It is not
/// an under-match that would let a covering deny through.
pub(crate) fn fold_case(text: &str) -> String {
    text.to_uppercase()
}
#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A root key never swallows the next segment: `C:\work` is not a
    /// prefix of `C:\work2`, and a single-backslash path is a real root
    /// (Win32 "root of the current drive"), not a relative spelling.
    #[test]
    fn the_root_semantics_cover_both_callers() {
        assert_eq!(
            split_path_root(r"\work\sub"),
            (r"\".to_string(), r"work\sub")
        );
        assert_ne!(
            path_key(r"\work\sub"),
            path_key(r"work\sub"),
            "a separator root is a real root"
        );
        assert_eq!(split_path_root(r"C:\work\sub").0, "C:");
        assert_ne!(
            path_key(r"C:\work"),
            path_key(r"C:\work2"),
            "a root key must not swallow the next segment's first character"
        );
    }    /// Path-key boundary inputs. Raw strings spell every separator unambiguously
    /// (Win32 comparison is the ground truth the key approximates).
    #[test]
    fn the_shared_path_key_boundaries_match_win32_comparison() {
        // Dot segments join away: an interior `\.`, a trailing `\.`, a trailing
        // separator, and a ` .` component are all the same path as their parent.
        assert_eq!(path_key(r"C:\work\.\sub"), path_key(r"C:\work\sub"));
        assert_eq!(path_key(r"C:\work\sub\."), path_key(r"C:\work\sub\"));
        assert_eq!(path_key(r"C:\work\sub \"), path_key(r"C:\work\sub\"));
        // A rootless path must NOT grow an artificial root separator.
        assert_ne!(path_key(r"work\sub"), r"\WORK\SUB");
        // The bare verbatim prefix (exactly four bytes) unifies away to nothing.
        assert_eq!(unify_path_prefix(r"\\?\"), "");
        // The device prefix unifies to its remainder.
        assert_eq!(unify_path_prefix(r"\\?\C:\work"), r"C:\work");
        // The verbatim UNC form unifies to the plain UNC form.
        assert_eq!(unify_path_prefix(r"\\?\UNC\srv\share"), r"\\srv\share");
        // UNC: the root is server+share; the remainder starts below it; a
        // shareless root invents no share separator; trailing dots trim.
        assert_eq!(split_path_root(r"\\srv").0, r"\\srv");
        assert_eq!(split_path_root(r"\\srv").1, "");
        let (root, rest) = split_path_root(r"\\srv\share\child\x");
        assert_eq!(root, r"\\srv\share");
        // The remainder keeps the separator before the first segment below the
        // share; path_key's segment pass skips the empty first segment, so the
        // join never doubles the separator.
        assert_eq!(rest, r"\child\x");
        assert_eq!(
            split_path_root(r"\\srv\share.\child"),
            (r"\\srv\share".to_string(), r"\child")
        );
    }


}
