use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::EngineConfig;
use crate::domain::{LineRange, ProjectPath};
use crate::errors::EngineError;

use super::filesystem::ProjectFilesystem;
use super::{exclusions, language};

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileContent {
    pub path: PathBuf,
    pub content: String,
    pub total_lines: u32,
    pub language: Option<String>,
    pub range: Option<LineRange>,
}

pub fn read_project_file(
    filesystem: &ProjectFilesystem,
    path: &ProjectPath,
    range: Option<LineRange>,
    config: &EngineConfig,
) -> Result<FileContent, EngineError> {
    let requested_path = filesystem.absolute_path(path);
    ensure_policy_allows(filesystem, &requested_path, config)?;
    let resolved_path = filesystem.project_path(&requested_path)?;
    let absolute_path = filesystem.absolute_path(&resolved_path);
    ensure_policy_allows(filesystem, &absolute_path, config)?;

    let mut file = filesystem.open_file(&resolved_path)?;
    let declared_len = file.metadata().map(|metadata| metadata.len());
    let raw_bytes = read_within_limit(
        &mut file,
        declared_len,
        &absolute_path,
        config.max_file_size_bytes,
    )?;
    let full_content = String::from_utf8(raw_bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
    Ok(build_file_content(&absolute_path, full_content, range))
}

fn ensure_policy_allows(
    filesystem: &ProjectFilesystem,
    path: &Path,
    config: &EngineConfig,
) -> Result<(), EngineError> {
    let excluded = exclusions::is_excluded(path, config)
        || exclusions::is_git_ignored(filesystem.root().as_path(), path, config);
    if excluded {
        return Err(EngineError::ExcludedPath(path.to_path_buf()));
    }
    Ok(())
}

fn read_within_limit(
    source: &mut impl Read,
    declared_len: std::io::Result<u64>,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, EngineError> {
    let declared_len = declared_len.map_err(|error| io_error(path, error))?;
    require_size_within_limit(path, declared_len, max_bytes)?;

    let mut raw_bytes = Vec::with_capacity(declared_len as usize);
    source
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw_bytes)
        .map_err(|error| io_error(path, error))?;
    require_size_within_limit(path, raw_bytes.len() as u64, max_bytes)?;

    Ok(raw_bytes)
}

fn require_size_within_limit(
    path: &Path,
    size_bytes: u64,
    max_bytes: u64,
) -> Result<(), EngineError> {
    if size_bytes > max_bytes {
        return Err(EngineError::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes,
            max_bytes,
        });
    }
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> EngineError {
    EngineError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn build_file_content(path: &Path, full_content: String, range: Option<LineRange>) -> FileContent {
    let total_lines = u32::try_from(full_content.lines().count()).unwrap_or(u32::MAX);
    let language = language::detect(path, full_content.lines().next()).map(String::from);
    let (content, applied_range) = apply_line_range(full_content, range);
    FileContent {
        path: path.to_path_buf(),
        content,
        total_lines,
        language,
        range: applied_range,
    }
}

fn apply_line_range(full_content: String, range: Option<LineRange>) -> (String, Option<LineRange>) {
    let Some(range) = range else {
        return (full_content, None);
    };
    let start = usize::try_from(range.start().saturating_sub(1)).unwrap_or(usize::MAX);
    let line_count = usize::try_from(range.end().saturating_sub(range.start()).saturating_add(1))
        .unwrap_or(usize::MAX);
    let mut selected = String::new();
    for (index, line) in full_content
        .lines()
        .skip(start)
        .take(line_count)
        .enumerate()
    {
        if index > 0 {
            selected.push('\n');
        }
        selected.push_str(line);
    }
    (selected, Some(range))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::domain::ProjectRoot;
    use std::fs;
    use tempfile::TempDir;

    fn read(
        directory: &TempDir,
        relative_path: &str,
        range: Option<LineRange>,
    ) -> Result<FileContent, EngineError> {
        let root = ProjectRoot::open(directory.path()).unwrap();
        let filesystem = ProjectFilesystem::open(root).unwrap();
        let path = ProjectPath::parse(Path::new(relative_path)).unwrap();
        read_project_file(&filesystem, &path, range, &default_config())
    }

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    #[test]
    fn reads_full_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.rs");
        fs::write(&file, "line 1\nline 2\nline 3").unwrap();

        let result = read(&dir, "test.rs", None).unwrap();

        assert_eq!(result.total_lines, 3);
        assert_eq!(result.content, "line 1\nline 2\nline 3");
        assert_eq!(result.language.as_deref(), Some("rust"));
        assert!(result.range.is_none());
    }

    #[test]
    fn reads_line_range() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "line 1\nline 2\nline 3\nline 4\nline 5").unwrap();

        let range = LineRange::new(2, 4).unwrap();
        let result = read(&dir, "test.txt", Some(range)).unwrap();

        assert_eq!(result.content, "line 2\nline 3\nline 4");
        assert_eq!(result.total_lines, 5);
        assert!(result.range.is_some());
    }

    #[test]
    fn returns_error_for_missing_file() {
        let directory = TempDir::new().unwrap();
        let result = read(&directory, "missing.rs", None);
        assert!(matches!(result, Err(EngineError::FileNotFound(_))));
    }

    #[test]
    fn returns_error_for_oversized_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("large.txt");
        fs::write(&file, "x".repeat(2_000_000)).unwrap();

        let result = read(&dir, "large.txt", None);
        assert!(matches!(result, Err(EngineError::FileTooLarge { .. })));
    }

    #[test]
    fn handles_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.txt");
        fs::write(&file, "").unwrap();

        let result = read(&dir, "empty.txt", None).unwrap();

        assert_eq!(result.total_lines, 0);
        assert!(result.content.is_empty());
    }

    #[test]
    fn clamps_range_to_file_bounds() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("short.txt");
        fs::write(&file, "line 1\nline 2").unwrap();

        let range = LineRange::new(1, 100).unwrap();
        let result = read(&dir, "short.txt", Some(range)).unwrap();

        assert_eq!(result.content, "line 1\nline 2");
    }

    #[test]
    fn handles_lossy_utf8() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("binary_ish.txt");
        let mut content = b"hello ".to_vec();
        content.extend_from_slice(&[0xFF, 0xFE]);
        content.extend_from_slice(b" world");
        fs::write(&file, &content).unwrap();

        let result = read(&dir, "binary_ish.txt", None).unwrap();
        assert!(result.content.contains("hello"));
        assert!(result.content.contains("world"));
    }

    #[test]
    fn full_file_range_reuses_the_source_allocation() {
        let source = String::from("line 1\nline 2");
        let allocation = source.as_ptr();

        let (content, range) = apply_line_range(source, None);

        assert_eq!(content.as_ptr(), allocation);
        assert!(range.is_none());
    }

    #[test]
    fn rejects_excluded_paths_before_opening_them() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join(".env"), "SECRET=value").unwrap();

        let error = read(&directory, ".env", None).unwrap_err();

        assert!(matches!(error, EngineError::ExcludedPath(_)));
    }

    #[test]
    fn directory_reads_preserve_the_io_error_path() {
        let directory = TempDir::new().unwrap();
        fs::create_dir(directory.path().join("folder")).unwrap();

        let error = read(&directory, "folder", None).unwrap_err();

        assert!(matches!(
            error,
            EngineError::NotRegularFile(path) if path.ends_with("folder")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn virtual_files_growing_past_the_metadata_size_hit_the_stream_limit() {
        let root = ProjectRoot::open(Path::new("/proc/self")).unwrap();
        let filesystem = ProjectFilesystem::open(root).unwrap();
        let path = ProjectPath::parse(Path::new("status")).unwrap();
        let config = EngineConfig {
            max_file_size_bytes: 1,
            ..EngineConfig::default()
        };

        let error = read_project_file(&filesystem, &path, None, &config).unwrap_err();

        assert!(matches!(
            error,
            EngineError::FileTooLarge {
                size_bytes: 2,
                max_bytes: 1,
                ..
            }
        ));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn an_unreadable_file_size_keeps_the_path_in_the_io_error() {
        let error = read_within_limit(
            &mut std::io::empty(),
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Path::new("/project/main.rs"),
            1024,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EngineError::Io { path, source }
                if path == Path::new("/project/main.rs")
                    && source.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn a_declared_size_over_the_limit_is_rejected_before_reading() {
        let error = read_within_limit(&mut FailingReader, Ok(4096), Path::new("big.bin"), 1024)
            .unwrap_err();

        assert!(matches!(
            error,
            EngineError::FileTooLarge {
                path,
                size_bytes: 4096,
                max_bytes: 1024,
            } if path == Path::new("big.bin")
        ));
    }

    #[test]
    fn a_failing_read_keeps_the_path_in_the_io_error() {
        let error = read_within_limit(&mut FailingReader, Ok(8), Path::new("stream.bin"), 1024)
            .unwrap_err();

        assert!(matches!(
            error,
            EngineError::Io { path, source }
                if path == Path::new("stream.bin")
                    && source.kind() == std::io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn a_source_understating_its_size_is_rejected_after_reading() {
        let mut source = std::io::Cursor::new(vec![b'x'; 32]);

        let error = read_within_limit(&mut source, Ok(0), Path::new("virtual.txt"), 8).unwrap_err();

        assert!(matches!(
            error,
            EngineError::FileTooLarge {
                size_bytes: 9,
                max_bytes: 8,
                ..
            }
        ));
    }

    #[test]
    fn a_source_within_the_limit_returns_every_byte() {
        let mut source = std::io::Cursor::new(b"payload".to_vec());

        let bytes = read_within_limit(&mut source, Ok(7), Path::new("ok.txt"), 1024).unwrap();

        assert_eq!(bytes, b"payload".to_vec());
    }
}
