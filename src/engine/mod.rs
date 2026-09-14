pub mod ast;
pub mod exclusions;
pub mod filesystem;
pub mod inventory;
pub mod language;
pub mod reader;
pub mod searcher;
pub mod stats;
pub mod walker;

use std::collections::BTreeSet;
use std::path::Path;

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::domain::ProjectPath;
use crate::errors::EngineError;

pub use crate::domain::LineRange;
pub use filesystem::ProjectFilesystem;
pub use inventory::ProjectInventory;
pub use reader::FileContent;
pub use searcher::{SearchOpts, TextMatch};
pub use stats::ProjectStats;
pub use walker::{DiscoverOpts, FileEntry};

pub trait Engine: Send + Sync {
    fn discover_files(
        &self,
        root: &Path,
        opts: &DiscoverOpts,
    ) -> Result<Vec<FileEntry>, EngineError>;

    fn discover_files_cancellable(
        &self,
        root: &Path,
        opts: &DiscoverOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<FileEntry>, EngineError> {
        ensure_not_cancelled(cancel)?;
        let result = self.discover_files(root, opts)?;
        ensure_not_cancelled(cancel)?;
        Ok(result)
    }

    fn search_project_text(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError>;

    fn search_project_text_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<TextMatch>, EngineError> {
        ensure_not_cancelled(cancel)?;
        let result = self.search_project_text(filesystem, pattern, opts)?;
        ensure_not_cancelled(cancel)?;
        Ok(result)
    }

    fn search_inventory_text(
        &self,
        inventory: &ProjectInventory,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError>;

    fn search_inventory_entries(
        &self,
        inventory: &ProjectInventory,
        entries: &[FileEntry],
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError> {
        let allowed_paths: BTreeSet<&Path> =
            entries.iter().map(|entry| entry.path.as_path()).collect();
        let mut matches = self.search_inventory_text(inventory, pattern, opts)?;
        matches.retain(|found| allowed_paths.contains(found.path.as_path()));
        Ok(matches)
    }

    fn search_inventory_entries_cancellable(
        &self,
        inventory: &ProjectInventory,
        entries: &[FileEntry],
        pattern: &str,
        opts: &SearchOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<TextMatch>, EngineError> {
        ensure_not_cancelled(cancel)?;
        let result = self.search_inventory_entries(inventory, entries, pattern, opts)?;
        ensure_not_cancelled(cancel)?;
        Ok(result)
    }

    fn read_project_file(
        &self,
        filesystem: &ProjectFilesystem,
        path: &ProjectPath,
        range: Option<LineRange>,
    ) -> Result<FileContent, EngineError>;

    fn is_path_excluded(&self, path: &Path) -> bool;

    fn is_path_ignored_by_repository(&self, project_root: &Path, path: &Path) -> bool;

    fn project_stats_with_capability(
        &self,
        filesystem: &ProjectFilesystem,
    ) -> Result<ProjectStats, EngineError>;

    fn project_stats_with_capability_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        cancel: &CancelToken,
    ) -> Result<ProjectStats, EngineError> {
        ensure_not_cancelled(cancel)?;
        let result = self.project_stats_with_capability(filesystem)?;
        ensure_not_cancelled(cancel)?;
        Ok(result)
    }
}

fn ensure_not_cancelled(cancel: &CancelToken) -> Result<(), EngineError> {
    if cancel.is_cancelled() {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

pub struct DefaultEngine {
    config: EngineConfig,
}

impl DefaultEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self { config }
    }
}

impl Engine for DefaultEngine {
    fn discover_files(
        &self,
        root: &Path,
        opts: &DiscoverOpts,
    ) -> Result<Vec<FileEntry>, EngineError> {
        walker::walk_project(root, &self.config, opts)
    }

    fn discover_files_cancellable(
        &self,
        root: &Path,
        opts: &DiscoverOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<FileEntry>, EngineError> {
        let project_root =
            crate::domain::ProjectRoot::open(root).map_err(|error| EngineError::Io {
                path: root.to_path_buf(),
                source: std::io::Error::other(error),
            })?;
        let filesystem = ProjectFilesystem::open(project_root)?;
        Ok(walker::walk_project_with_capability_cancellable(
            &filesystem,
            &self.config,
            opts,
            cancel,
        )?
        .files)
    }

    fn search_project_text(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError> {
        searcher::search_project_text(filesystem, pattern, opts, &self.config)
    }

    fn search_project_text_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<TextMatch>, EngineError> {
        searcher::search_project_text_cancellable(filesystem, pattern, opts, &self.config, cancel)
    }

    fn search_inventory_text(
        &self,
        inventory: &ProjectInventory,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError> {
        searcher::search_project_entries(
            inventory.filesystem(),
            inventory.files(),
            pattern,
            opts,
            &self.config,
        )
    }

    fn search_inventory_entries(
        &self,
        inventory: &ProjectInventory,
        entries: &[FileEntry],
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, EngineError> {
        searcher::search_project_entries(
            inventory.filesystem(),
            entries,
            pattern,
            opts,
            &self.config,
        )
    }

    fn search_inventory_entries_cancellable(
        &self,
        inventory: &ProjectInventory,
        entries: &[FileEntry],
        pattern: &str,
        opts: &SearchOpts,
        cancel: &CancelToken,
    ) -> Result<Vec<TextMatch>, EngineError> {
        searcher::search_project_entries_cancellable(
            inventory.filesystem(),
            entries,
            pattern,
            opts,
            &self.config,
            cancel,
        )
    }

    fn read_project_file(
        &self,
        filesystem: &ProjectFilesystem,
        path: &ProjectPath,
        range: Option<LineRange>,
    ) -> Result<FileContent, EngineError> {
        reader::read_project_file(filesystem, path, range, &self.config)
    }

    fn is_path_excluded(&self, path: &Path) -> bool {
        exclusions::is_excluded(path, &self.config)
    }

    fn is_path_ignored_by_repository(&self, project_root: &Path, path: &Path) -> bool {
        exclusions::is_git_ignored(project_root, path, &self.config)
    }

    fn project_stats_with_capability(
        &self,
        filesystem: &ProjectFilesystem,
    ) -> Result<ProjectStats, EngineError> {
        stats::project_stats_with_capability(filesystem, &self.config)
    }

    fn project_stats_with_capability_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        cancel: &CancelToken,
    ) -> Result<ProjectStats, EngineError> {
        stats::project_stats_with_capability_cancellable(filesystem, &self.config, cancel)
    }
}
