use std::path::Path;

use crate::config;
use crate::config::loader::TrustedConfigSource;
use crate::domain::ProjectRoot;
use crate::errors::BugHunterError;

pub(super) struct TrustedProject {
    pub root: ProjectRoot,
    pub source: TrustedConfigSource,
    pub config: config::schema::Config,
}

pub(super) fn open(
    project: &Path,
    explicit_config: Option<&Path>,
) -> Result<TrustedProject, BugHunterError> {
    let root = ProjectRoot::open(project)?;
    let source = TrustedConfigSource::for_local_checkout(root.as_path(), explicit_config);
    let config = config::loader::load_config(&source)?;
    Ok(TrustedProject {
        root,
        source,
        config,
    })
}
