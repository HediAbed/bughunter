use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata};

use crate::domain::{ProjectPath, ProjectRoot};
use crate::errors::EngineError;
use crate::shared::canonicalize_path_with_missing_leaf;

pub struct ProjectFilesystem {
    root: ProjectRoot,
    directory: Dir,
}

impl ProjectFilesystem {
    pub fn open(root: ProjectRoot) -> Result<Self, EngineError> {
        let directory =
            Dir::open_ambient_dir(root.as_path(), ambient_authority()).map_err(|source| {
                EngineError::Io {
                    path: root.as_path().to_path_buf(),
                    source,
                }
            })?;
        Ok(Self { root, directory })
    }

    pub fn root(&self) -> &ProjectRoot {
        &self.root
    }

    pub fn absolute_path(&self, path: &ProjectPath) -> PathBuf {
        self.root.as_path().join(path.as_path())
    }

    pub fn open_file(&self, path: &ProjectPath) -> Result<File, EngineError> {
        let absolute_path = self.absolute_path(path);
        let file = self.open_for_read(path, &absolute_path)?;
        require_regular_file(file, &absolute_path)
    }

    #[cfg(unix)]
    fn open_for_read(&self, path: &ProjectPath, absolute_path: &Path) -> Result<File, EngineError> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        cap_std::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
        self.directory
            .open_with(path.as_path(), &options)
            .map_err(|source| map_open_error(absolute_path.to_path_buf(), source))
    }

    #[cfg(not(unix))]
    fn open_for_read(&self, path: &ProjectPath, absolute_path: &Path) -> Result<File, EngineError> {
        self.directory
            .open(path.as_path())
            .map_err(|source| map_open_error(absolute_path.to_path_buf(), source))
    }

    pub fn metadata(&self, path: &ProjectPath) -> Result<cap_std::fs::Metadata, EngineError> {
        self.directory
            .metadata(path.as_path())
            .map_err(|source| map_open_error(self.absolute_path(path), source))
    }

    pub fn project_path(&self, absolute_path: &Path) -> Result<ProjectPath, EngineError> {
        let resolved_path =
            canonicalize_path_with_missing_leaf(absolute_path).map_err(|source| {
                EngineError::Io {
                    path: absolute_path.to_path_buf(),
                    source,
                }
            })?;
        let relative_path = resolved_path
            .strip_prefix(self.root.as_path())
            .map_err(|_| EngineError::ExcludedPath(absolute_path.to_path_buf()))?;
        ProjectPath::parse(relative_path)
            .map_err(|_| EngineError::ExcludedPath(absolute_path.to_path_buf()))
    }
}

fn require_regular_file(file: File, path: &Path) -> Result<File, EngineError> {
    let metadata = file.metadata();
    accept_regular_file(file, path, metadata)
}

fn accept_regular_file(
    file: File,
    path: &Path,
    metadata: std::io::Result<Metadata>,
) -> Result<File, EngineError> {
    let metadata = metadata.map_err(|source| map_open_error(path.to_path_buf(), source))?;
    if metadata.file_type().is_file() {
        return Ok(file);
    }
    Err(EngineError::NotRegularFile(path.to_path_buf()))
}

fn map_open_error(path: PathBuf, source: std::io::Error) -> EngineError {
    if source.kind() == std::io::ErrorKind::NotFound {
        EngineError::FileNotFound(path)
    } else {
        EngineError::Io { path, source }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Read;
    use tempfile::TempDir;

    fn filesystem(directory: &TempDir) -> ProjectFilesystem {
        ProjectFilesystem::open(ProjectRoot::open(directory.path()).unwrap()).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_resolving_outside_the_project() {
        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "secret").unwrap();
        let link = project.path().join("linked.txt");
        std::os::unix::fs::symlink(secret, &link).unwrap();

        let error = filesystem(&project).project_path(&link).unwrap_err();

        assert!(matches!(error, EngineError::ExcludedPath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_broken_symlinks() {
        let project = TempDir::new().unwrap();
        let link = project.path().join("linked.txt");
        std::os::unix::fs::symlink(project.path().join("missing.txt"), &link).unwrap();
        let filesystem = filesystem(&project);
        let path = filesystem.project_path(&link).unwrap();

        let error = filesystem.open_file(&path).unwrap_err();

        assert!(matches!(
            error,
            EngineError::FileNotFound(_) | EngineError::Io { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_cyclic_symlinks() {
        let project = TempDir::new().unwrap();
        let first = project.path().join("first.txt");
        let second = project.path().join("second.txt");
        std::os::unix::fs::symlink(&second, &first).unwrap();
        std::os::unix::fs::symlink(&first, &second).unwrap();

        let error = filesystem(&project).project_path(&first).unwrap_err();

        assert!(matches!(error, EngineError::Io { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn resolved_paths_ignore_later_symlink_swaps() {
        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let source = project.path().join("source.txt");
        let secret = outside.path().join("secret.txt");
        let link = project.path().join("linked.txt");
        std::fs::write(&source, "inside").unwrap();
        std::fs::write(&secret, "outside").unwrap();
        std::os::unix::fs::symlink(&source, &link).unwrap();
        let filesystem = filesystem(&project);
        let resolved_path = filesystem.project_path(&link).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let mut content = String::new();
        filesystem
            .open_file(&resolved_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert_eq!(content, "inside");
    }

    #[test]
    fn opening_a_project_removed_after_validation_returns_contextual_io_error() {
        let project = TempDir::new().unwrap();
        let root = ProjectRoot::open(project.path()).unwrap();
        let expected_path = root.as_path().to_path_buf();
        project.close().unwrap();

        let error = match ProjectFilesystem::open(root) {
            Ok(_) => panic!("a removed project root must fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EngineError::Io { path, .. } if path == expected_path
        ));
    }
    #[test]
    fn opening_a_directory_returns_not_regular_file() {
        let project = TempDir::new().unwrap();
        std::fs::create_dir(project.path().join("subdir")).unwrap();
        let filesystem = filesystem(&project);
        let path = filesystem
            .project_path(&project.path().join("subdir"))
            .unwrap();

        let error = filesystem.open_file(&path).unwrap_err();

        assert!(matches!(error, EngineError::NotRegularFile(_)));
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_fifo_fails_fast_instead_of_blocking() {
        let project = TempDir::new().unwrap();
        let fifo = project.path().join("pipe");
        let raw_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        let created = unsafe { libc::mkfifo(raw_path.as_ptr(), 0o644) };
        assert_eq!(
            created,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
        let filesystem = filesystem(&project);
        let path = filesystem.project_path(&fifo).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(filesystem.open_file(&path));
        });

        let outcome = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("opening a fifo must not block");

        assert!(matches!(outcome, Err(EngineError::NotRegularFile(_))));
    }

    #[test]
    fn metadata_for_a_missing_project_path_returns_not_found() {
        let project = TempDir::new().unwrap();
        let filesystem = filesystem(&project);
        let path = filesystem
            .project_path(&project.path().join("missing.txt"))
            .unwrap();

        let error = filesystem.metadata(&path).unwrap_err();

        assert!(matches!(error, EngineError::FileNotFound(_)));
    }

    #[test]
    fn acceptance_maps_a_metadata_failure_and_still_screens_irregular_files() {
        let project = TempDir::new().unwrap();
        std::fs::write(project.path().join("file.txt"), "body").unwrap();
        std::fs::create_dir(project.path().join("directory")).unwrap();
        let filesystem = filesystem(&project);
        let file_path = filesystem
            .project_path(&project.path().join("file.txt"))
            .unwrap();
        let absolute = project.path().join("file.txt");

        let opened = filesystem.open_file(&file_path).unwrap();
        let metadata = opened.metadata();
        assert!(accept_regular_file(opened, &absolute, metadata).is_ok());

        let opened = filesystem.open_file(&file_path).unwrap();
        let error = accept_regular_file(
            opened,
            &absolute,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        )
        .unwrap_err();
        match error {
            EngineError::Io { path, source } => {
                assert_eq!(path, absolute);
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected an I/O error, got {other:?}"),
        }

        let directory_path = filesystem
            .project_path(&project.path().join("directory"))
            .unwrap();
        let directory_metadata = filesystem.metadata(&directory_path).unwrap();
        let opened = filesystem.open_file(&file_path).unwrap();
        let error = accept_regular_file(opened, &absolute, Ok(directory_metadata)).unwrap_err();
        assert!(matches!(error, EngineError::NotRegularFile(_)));
    }
}
