//! Built-in network profiles (`minimal`, `developer`, `none`).
//!
//! These are hardcoded in the binary, not files on disk. A profile name in
//! the user's profile JSON (or the `--network-profile` CLI flag) resolves to
//! one of these. `none` is an alias for `--block-net`.

pub fn builtin_profile(name: &str) -> Option<Vec<String>> {
    match name {
        "none" => Some(Vec::new()), // block-net; empty list is irrelevant
        "minimal" => Some(vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "generativelanguage.googleapis.com".into(),
        ]),
        "developer" => {
            let mut v = builtin_profile("minimal").unwrap();
            v.extend([
                "registry.npmjs.org".into(),
                "registry.npmjs.com".into(),
                "pypi.org".into(),
                "files.pythonhosted.org".into(),
                "crates.io".into(),
                "static.crates.io".into(),
                "github.com".into(),
                "objects.githubusercontent.com".into(),
                "raw.githubusercontent.com".into(),
                "codeload.github.com".into(),
            ]);
            Some(v)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_covers_llm_apis() {
        let p = builtin_profile("minimal").unwrap();
        assert!(p.contains(&"api.openai.com".into()));
        assert!(p.contains(&"api.anthropic.com".into()));
        assert!(p.contains(&"generativelanguage.googleapis.com".into()));
        assert!(!p.contains(&"github.com".into()));
    }

    #[test]
    fn developer_adds_registries_and_github() {
        let p = builtin_profile("developer").unwrap();
        for h in ["api.openai.com","registry.npmjs.org","pypi.org","crates.io","github.com"] {
            assert!(p.iter().any(|x| x == h), "developer profile missing {h}");
        }
    }

    #[test]
    fn none_is_empty() {
        assert!(builtin_profile("none").unwrap().is_empty());
    }

    #[test]
    fn unknown_returns_none() {
        assert!(builtin_profile("bogus").is_none());
    }
}
