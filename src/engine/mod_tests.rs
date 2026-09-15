use super::*;
use crate::cancel::CancelToken;
use crate::domain::ProjectRoot;
use tempfile::TempDir;

fn project() -> TempDir {
    let directory = TempDir::new().unwrap();
    std::fs::write(
        directory.path().join("alpha.rs"),
        "fn alpha() {\n    let value = 1;\n    let _ = value;\n}\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("beta.rs"),
        "fn beta() {\n    let other = 2;\n    let _ = other;\n}\n",
    )
    .unwrap();
    directory
}

fn engine() -> DefaultEngine {
    DefaultEngine::new(EngineConfig::default())
}

fn filesystem(directory: &TempDir) -> ProjectFilesystem {
    ProjectFilesystem::open(ProjectRoot::open(directory.path()).unwrap()).unwrap()
}

fn inventory(directory: &TempDir) -> ProjectInventory {
    ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap()
}

fn search_options() -> SearchOpts {
    SearchOpts {
        case_sensitive: false,
        file_extensions: None,
        max_results: None,
        context_lines: 0,
    }
}

#[test]
fn discovery_reports_every_file_and_honours_cancellation() {
    let directory = project();
    let engine = engine();
    let live = CancelToken::default();

    let discovered = engine
        .discover_files_cancellable(directory.path(), &DiscoverOpts::default(), &live)
        .unwrap();

    assert_eq!(discovered.len(), 2);

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let error = engine
        .discover_files_cancellable(directory.path(), &DiscoverOpts::default(), &cancelled)
        .unwrap_err();

    assert!(matches!(error, EngineError::Cancelled));
}

#[test]
fn a_discovery_root_that_cannot_be_opened_reports_io() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing");

    let error = engine()
        .discover_files_cancellable(&missing, &DiscoverOpts::default(), &CancelToken::default())
        .unwrap_err();

    assert!(matches!(error, EngineError::Io { .. }));
}

#[test]
fn project_search_matches_and_honours_cancellation() {
    let directory = project();
    let engine = engine();
    let filesystem = filesystem(&directory);

    let found = engine
        .search_project_text_cancellable(
            &filesystem,
            "let value",
            &search_options(),
            &CancelToken::default(),
        )
        .unwrap();

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line_number, 2);

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let error = engine
        .search_project_text_cancellable(&filesystem, "let value", &search_options(), &cancelled)
        .unwrap_err();

    assert!(matches!(error, EngineError::Cancelled));
}

#[test]
fn inventory_entry_search_restricts_results_to_the_named_entries() {
    let directory = project();
    let engine = engine();
    let inventory = inventory(&directory);
    let only_alpha: Vec<FileEntry> = inventory
        .files()
        .iter()
        .filter(|entry| entry.relative_path == "alpha.rs")
        .cloned()
        .collect();

    let scoped = engine
        .search_inventory_entries(&inventory, &only_alpha, "fn ", &search_options())
        .unwrap();
    let everything = engine
        .search_inventory_entries(&inventory, inventory.files(), "fn ", &search_options())
        .unwrap();

    assert_eq!(scoped.len(), 1);
    assert!(scoped[0].path.ends_with("alpha.rs"));
    assert_eq!(everything.len(), 2);
}

#[test]
fn inventory_entry_search_honours_cancellation() {
    let directory = project();
    let engine = engine();
    let inventory = inventory(&directory);
    let entries = inventory.files().to_vec();

    let found = engine
        .search_inventory_entries_cancellable(
            &inventory,
            &entries,
            "fn ",
            &search_options(),
            &CancelToken::default(),
        )
        .unwrap();

    assert_eq!(found.len(), 2);

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let error = engine
        .search_inventory_entries_cancellable(
            &inventory,
            &entries,
            "fn ",
            &search_options(),
            &cancelled,
        )
        .unwrap_err();

    assert!(matches!(error, EngineError::Cancelled));
}

#[test]
fn project_statistics_count_files_and_honour_cancellation() {
    let directory = project();
    let engine = engine();
    let filesystem = filesystem(&directory);

    let stats = engine
        .project_stats_with_capability_cancellable(&filesystem, &CancelToken::default())
        .unwrap();

    assert_eq!(stats.total_files, 2);

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let error = engine
        .project_stats_with_capability_cancellable(&filesystem, &cancelled)
        .unwrap_err();

    assert!(matches!(error, EngineError::Cancelled));
}
