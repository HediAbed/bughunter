use std::borrow::Cow;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::errors::ConfigError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectRoot(PathBuf);

impl ProjectRoot {
    pub fn open(path: &Path) -> Result<Self, ConfigError> {
        let requested_path = path;
        let canonical_path = match requested_path.canonicalize() {
            Ok(canonical_path) => canonical_path,
            Err(source) => {
                return Err(ConfigError::InvalidValue {
                    field: "project".into(),
                    reason: format!("cannot resolve {}: {source}", requested_path.display()),
                });
            }
        };
        if !canonical_path.is_dir() {
            return Err(ConfigError::InvalidValue {
                field: "project".into(),
                reason: format!("not a directory: {}", canonical_path.display()),
            });
        }
        Ok(Self(canonical_path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for ProjectRoot {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl std::fmt::Display for ProjectRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_path().display().fmt(formatter)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectPath(PathBuf);

impl ProjectPath {
    pub fn parse(path: &Path) -> Result<Self, ProjectPathError> {
        let requested_path = path;
        let requested_text = match requested_path.to_str() {
            Some(value) => value,
            None => return Err(ProjectPathError::NonUnicode),
        };
        if requested_text.contains(':') {
            return Err(ProjectPathError::WindowsNamespace);
        }
        let normalized_text = if requested_text.contains('\\') {
            Cow::Owned(requested_text.replace('\\', "/"))
        } else {
            Cow::Borrowed(requested_text)
        };
        let normalized_request = Path::new(normalized_text.as_ref());
        let mut normalized_path = PathBuf::new();
        for component in normalized_request.components() {
            match component {
                std::path::Component::Normal(part) => normalized_path.push(part),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    return Err(ProjectPathError::ParentTraversal);
                }
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                    return Err(ProjectPathError::Absolute);
                }
            }
        }
        if normalized_path.as_os_str().is_empty() {
            return Err(ProjectPathError::Empty);
        }
        Ok(Self(normalized_path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn key(&self) -> String {
        self.0.to_string_lossy().replace('\\', "/")
    }
}

impl AsRef<Path> for ProjectPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProjectPathError {
    #[error("path must identify a project file")]
    Empty,
    #[error("path must be relative to the project root")]
    Absolute,
    #[error("parent path traversal is not allowed")]
    ParentTraversal,
    #[error("path must use Unicode characters")]
    NonUnicode,
    #[error("Windows drive and alternate-stream paths are not allowed")]
    WindowsNamespace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LineRange {
    start: NonZeroU32,
    end: NonZeroU32,
}

impl LineRange {
    pub fn new(start: u32, end: u32) -> Result<Self, LineRangeError> {
        let start = NonZeroU32::new(start).ok_or(LineRangeError::ZeroStart)?;
        let end = NonZeroU32::new(end).ok_or(LineRangeError::ZeroEnd)?;
        if end < start {
            return Err(LineRangeError::Reversed {
                start: start.get(),
                end: end.get(),
            });
        }
        Ok(Self { start, end })
    }

    pub fn start(self) -> u32 {
        self.start.get()
    }

    pub fn end(self) -> u32 {
        self.end.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LineRangeError {
    #[error("line range start must be greater than zero")]
    ZeroStart,
    #[error("line range end must be greater than zero")]
    ZeroEnd,
    #[error("line range end {end} precedes start {start}")]
    Reversed { start: u32, end: u32 },
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn project_root_is_canonical_and_directory_only() {
        let directory = tempfile::tempdir().unwrap();
        let root = ProjectRoot::open(&directory.path().join(".")).unwrap();

        assert_eq!(root.as_path(), directory.path().canonicalize().unwrap());
        assert!(ProjectRoot::open(&directory.path().join("missing")).is_err());
    }

    #[test]
    fn project_paths_apply_windows_security_semantics_on_every_platform() {
        assert_eq!(
            ProjectPath::parse(Path::new(r"src\main.rs"))
                .unwrap()
                .as_path(),
            Path::new("src/main.rs")
        );
        assert_eq!(
            ProjectPath::parse(Path::new(r"..\outside.rs")),
            Err(ProjectPathError::ParentTraversal)
        );
        assert_eq!(
            ProjectPath::parse(Path::new(r"C:\Windows\system.ini")),
            Err(ProjectPathError::WindowsNamespace)
        );
        assert_eq!(
            ProjectPath::parse(Path::new(r"\\server\share\secret")),
            Err(ProjectPathError::Absolute)
        );
        assert_eq!(
            ProjectPath::parse(Path::new("config.toml:alternate-stream")),
            Err(ProjectPathError::WindowsNamespace)
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_paths_reject_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));

        assert_eq!(ProjectPath::parse(&path), Err(ProjectPathError::NonUnicode));
    }

    #[test]
    fn line_range_requires_ordered_positive_lines() {
        assert_eq!(LineRange::new(2, 3).unwrap().start(), 2);
        assert_eq!(LineRange::new(2, 3).unwrap().end(), 3);
        assert_eq!(LineRange::new(0, 1), Err(LineRangeError::ZeroStart));
        assert_eq!(LineRange::new(1, 0), Err(LineRangeError::ZeroEnd));
        assert_eq!(
            LineRange::new(3, 2),
            Err(LineRangeError::Reversed { start: 3, end: 2 })
        );
    }

    #[test]
    fn project_root_supports_owned_borrowed_and_display_forms() {
        let directory = tempfile::tempdir().unwrap();
        let root = ProjectRoot::open(directory.path()).unwrap();
        let expected = directory.path().canonicalize().unwrap();

        assert_eq!(AsRef::<Path>::as_ref(&root), expected);
        assert_eq!(root.to_string(), expected.display().to_string());
        assert_eq!(root.into_path_buf(), expected);
    }

    #[test]
    fn project_path_rejects_empty_normalized_paths_and_supports_as_ref() {
        assert_eq!(
            ProjectPath::parse(Path::new(".")),
            Err(ProjectPathError::Empty)
        );
        assert_eq!(
            ProjectPath::parse(Path::new("././")),
            Err(ProjectPathError::Empty)
        );

        let path = ProjectPath::parse(Path::new("./src/./main.rs")).unwrap();
        assert_eq!(AsRef::<Path>::as_ref(&path), Path::new("src/main.rs"));
    }

    #[test]
    fn project_path_keys_reparse_to_the_same_path() {
        for requested in [
            r"src\engine\walker.rs",
            "./src/./main.rs",
            "src//lib///mod.rs",
            "docs/design notes.md",
            "...",
            " ",
        ] {
            let path = ProjectPath::parse(Path::new(requested)).expect("path names a project file");
            let key = path.key();

            assert!(!key.contains('\\'), "key {key:?} kept a Windows separator");
            assert!(
                key.split('/')
                    .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
                "key {key:?} contains a traversable segment"
            );
            assert_eq!(
                ProjectPath::parse(Path::new(&key)),
                Ok(path),
                "key {key:?} of {requested:?} does not reparse"
            );
        }
    }
}
