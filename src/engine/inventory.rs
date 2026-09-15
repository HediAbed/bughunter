use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::Path;

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::domain::ProjectRoot;
use crate::errors::EngineError;

use super::filesystem::ProjectFilesystem;
use super::stats::{self, ProjectStats};
use super::walker::{self, DiscoverOpts, FileEntry, UnreadableFile};

pub struct ProjectInventory {
    filesystem: ProjectFilesystem,
    files: Vec<FileEntry>,
    unreadable_files: Vec<UnreadableFile>,
    stats: ProjectStats,
}

impl ProjectInventory {
    pub fn build(root: &Path, config: &EngineConfig) -> Result<Self, EngineError> {
        Self::build_inner(root, config, None)
    }

    pub fn build_cancellable(
        root: &Path,
        config: &EngineConfig,
        cancel: &CancelToken,
    ) -> Result<Self, EngineError> {
        Self::build_inner(root, config, Some(cancel))
    }

    fn build_inner(
        root: &Path,
        config: &EngineConfig,
        cancel: Option<&CancelToken>,
    ) -> Result<Self, EngineError> {
        if cancel.is_some_and(CancelToken::is_cancelled) {
            return Err(EngineError::Cancelled);
        }
        let project_root = ProjectRoot::open(root).map_err(|error| EngineError::Io {
            path: root.to_path_buf(),
            source: std::io::Error::other(error),
        })?;
        let filesystem = ProjectFilesystem::open(project_root)?;
        let walk = match cancel {
            Some(cancel) => walker::walk_project_with_capability_cancellable(
                &filesystem,
                config,
                &DiscoverOpts::default(),
                cancel,
            )?,
            None => {
                walker::walk_project_with_capability(&filesystem, config, &DiscoverOpts::default())?
            }
        };
        let stats = match cancel {
            Some(cancel) => stats::project_stats_for_entries_cancellable(
                &filesystem,
                config,
                &walk.files,
                cancel,
            ),
            None => Ok(stats::project_stats_for_entries(
                &filesystem,
                config,
                &walk.files,
            )),
        };
        Self::assemble(filesystem, walk, stats)
    }

    fn assemble(
        filesystem: ProjectFilesystem,
        walk: walker::ProjectWalk,
        stats: Result<ProjectStats, EngineError>,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            filesystem,
            files: walk.files,
            unreadable_files: walk.unreadable,
            stats: stats?,
        })
    }

    pub fn filesystem(&self) -> &ProjectFilesystem {
        &self.filesystem
    }

    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }

    pub fn unreadable_files(&self) -> &[UnreadableFile] {
        &self.unreadable_files
    }

    pub fn stats(&self) -> &ProjectStats {
        &self.stats
    }

    pub fn select_files<'a>(
        &'a self,
        allowed_files: Option<&BTreeSet<String>>,
    ) -> Cow<'a, [FileEntry]> {
        match allowed_files {
            None => Cow::Borrowed(&self.files),
            Some(allowed) => Cow::Owned(
                self.files
                    .iter()
                    .filter(|entry| allowed.contains(&entry.relative_path))
                    .cloned()
                    .collect(),
            ),
        }
    }

    pub fn select_files_cancellable<'a>(
        &'a self,
        allowed_files: Option<&BTreeSet<String>>,
        cancel: &CancelToken,
    ) -> Result<Cow<'a, [FileEntry]>, EngineError> {
        if cancel.is_cancelled() {
            return Err(EngineError::Cancelled);
        }
        self.select_allowed_cancellable(allowed_files, cancel)
    }

    fn select_allowed_cancellable<'a>(
        &'a self,
        allowed_files: Option<&BTreeSet<String>>,
        cancel: &CancelToken,
    ) -> Result<Cow<'a, [FileEntry]>, EngineError> {
        match allowed_files {
            None => Ok(Cow::Borrowed(&self.files)),
            Some(allowed) => {
                let mut selected = Vec::new();
                for entry in &self.files {
                    if cancel.is_cancelled() {
                        return Err(EngineError::Cancelled);
                    }
                    if allowed.contains(&entry.relative_path) {
                        selected.push(entry.clone());
                    }
                }
                Ok(Cow::Owned(selected))
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_cancelled_inventory_stops_before_walking() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        let cancel = CancelToken::default();
        cancel.cancel();

        let error = match ProjectInventory::build_cancellable(
            directory.path(),
            &EngineConfig::default(),
            &cancel,
        ) {
            Err(error) => error,
            Ok(_) => panic!("a cancelled inventory must fail"),
        };

        assert!(matches!(error, EngineError::Cancelled));
    }

    #[test]
    fn an_oversized_ignore_line_fails_a_cancellable_inventory() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        std::fs::write(
            directory.path().join(".ignore"),
            format!(
                "{}\n",
                "a".repeat(crate::engine::exclusions::MAX_IGNORE_LINE_BYTES + 1)
            ),
        )
        .unwrap();

        let error = match ProjectInventory::build_cancellable(
            directory.path(),
            &EngineConfig::default(),
            &CancelToken::default(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("an ignore line past its budget must fail the walk"),
        };

        match error {
            EngineError::DiscoveryLimitExceeded { resource, limit } => {
                assert_eq!(resource, crate::engine::exclusions::IGNORE_LINE_BYTES);
                assert_eq!(
                    limit,
                    crate::engine::exclusions::MAX_IGNORE_LINE_BYTES as u64
                );
            }
            other => panic!("expected a discovery limit failure, got {other:?}"),
        }
    }

    #[test]
    fn a_cancelled_selection_stops_partway_through_the_entries() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        let inventory =
            ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
        let allowed: BTreeSet<String> = inventory
            .files()
            .iter()
            .map(|entry| entry.relative_path.clone())
            .collect();
        let cancel = CancelToken::default();
        cancel.cancel();

        let error = inventory
            .select_allowed_cancellable(Some(&allowed), &cancel)
            .expect_err("a cancelled scan must not keep selecting entries");

        assert!(matches!(error, EngineError::Cancelled));
    }

    #[test]
    fn a_failed_statistics_pass_fails_the_inventory() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        let project_root = ProjectRoot::open(directory.path()).unwrap();
        let filesystem = ProjectFilesystem::open(project_root).unwrap();
        let walk = walker::walk_project_with_capability(
            &filesystem,
            &EngineConfig::default(),
            &DiscoverOpts::default(),
        )
        .unwrap();

        let error = match ProjectInventory::assemble(filesystem, walk, Err(EngineError::Cancelled))
        {
            Err(error) => error,
            Ok(_) => panic!("a failed statistics pass must fail the inventory"),
        };

        assert!(matches!(error, EngineError::Cancelled));
    }

    #[test]
    fn a_cancelled_selection_refuses_to_hand_back_files() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        let inventory =
            ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
        let cancel = CancelToken::default();
        cancel.cancel();

        let error = inventory
            .select_files_cancellable(None, &cancel)
            .expect_err("a cancelled selection must fail");

        assert!(matches!(error, EngineError::Cancelled));
        assert!(!inventory.files().is_empty());
    }

    #[test]
    fn selects_files_without_rewalking_the_project() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        std::fs::write(directory.path().join("two.rs"), "fn two() {}\n").unwrap();
        let inventory =
            ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
        std::fs::write(directory.path().join("three.rs"), "fn three() {}\n").unwrap();
        let allowed = BTreeSet::from(["two.rs".to_string()]);

        let selected = inventory.select_files(Some(&allowed));

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].relative_path, "two.rs");
        assert_eq!(inventory.files().len(), 2);
        assert_eq!(inventory.stats().total_files, 2);
    }

    #[test]
    fn inventory_build_reports_an_invalid_project_root_as_io() {
        let directory = TempDir::new().unwrap();
        let missing = directory.path().join("missing");

        let error = match ProjectInventory::build(&missing, &EngineConfig::default()) {
            Ok(_) => panic!("an invalid project root must fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EngineError::Io { path, .. } if path == missing
        ));
    }

    #[test]
    fn selecting_without_a_filter_borrows_every_discovered_file() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("one.rs"), "fn one() {}\n").unwrap();
        let inventory =
            ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();

        let selected = inventory.select_files(None);

        assert!(matches!(selected, Cow::Borrowed(_)));
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn discovered_files_keep_a_deterministic_relative_path_order() {
        let directory = TempDir::new().unwrap();
        std::fs::create_dir(directory.path().join("zeta")).unwrap();
        std::fs::create_dir(directory.path().join("alpha")).unwrap();
        std::fs::write(directory.path().join("zeta/one.rs"), "fn one() {}\n").unwrap();
        std::fs::write(directory.path().join("alpha/two.rs"), "fn two() {}\n").unwrap();
        std::fs::write(directory.path().join("middle.rs"), "fn middle() {}\n").unwrap();
        let allowed = BTreeSet::from(["middle.rs".to_string(), "zeta/one.rs".to_string()]);

        let inventory =
            ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();

        let discovered: Vec<&str> = inventory
            .files()
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        let selection = inventory.select_files(Some(&allowed));
        let selected: Vec<&str> = selection
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        assert_eq!(discovered, vec!["alpha/two.rs", "middle.rs", "zeta/one.rs"]);
        assert_eq!(selected, vec!["middle.rs", "zeta/one.rs"]);
    }
}
