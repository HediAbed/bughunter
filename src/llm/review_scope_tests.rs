use super::*;
use crate::config::EngineConfig;
use tempfile::TempDir;

fn changed(spans: &[(&str, &[(u32, u32)])]) -> ChangedLines {
    let ranges: HunkRanges = spans
        .iter()
        .map(|(path, hunks)| ((*path).to_string(), hunks.to_vec()))
        .collect();
    ChangedLines::try_from(ranges).expect("well-formed hunks")
}

fn range(start: u32, end: u32) -> LineRange {
    LineRange::new(start, end).unwrap()
}

#[test]
fn changed_lines_report_the_files_they_cover() {
    let changed_lines = changed(&[("src/a.rs", &[(10, 12)]), ("src/b.rs", &[(1, 1)])]);

    assert!(changed_lines.covers("src/a.rs"));
    assert!(changed_lines.covers("src/b.rs"));
    assert!(!changed_lines.covers("src/untouched.rs"));
}

#[test]
fn overlap_accepts_only_ranges_touching_a_hunk() {
    let changed_lines = changed(&[("src/a.rs", &[(10, 12), (40, 40)])]);

    for (start, end) in [(10, 10), (12, 20), (5, 10), (1, 100), (40, 40)] {
        assert!(
            changed_lines.overlaps("src/a.rs", range(start, end)),
            "{start}-{end} touches a changed hunk"
        );
    }
    for (start, end) in [(1, 9), (13, 39), (41, 60)] {
        assert!(
            !changed_lines.overlaps("src/a.rs", range(start, end)),
            "{start}-{end} lies between the changed hunks"
        );
    }
}

#[test]
fn overlap_is_false_for_files_outside_the_diff() {
    let changed_lines = changed(&[("src/a.rs", &[(1, 5)])]);

    assert!(!changed_lines.overlaps("src/b.rs", range(1, 5)));
}

#[test]
fn changed_lines_survive_a_json_round_trip() {
    let changed_lines = changed(&[("src/a.rs", &[(3, 7), (20, 21)])]);

    let encoded = serde_json::to_string(&changed_lines).unwrap();
    let decoded: ChangedLines = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, changed_lines);
    assert_eq!(encoded, r#"{"src/a.rs":[[3,7],[20,21]]}"#);
}

#[test]
fn decoding_rejects_hunks_that_are_not_line_ranges() {
    for raw in [r#"{"src/a.rs":[[0,4]]}"#, r#"{"src/a.rs":[[9,4]]}"#] {
        let error = serde_json::from_str::<ChangedLines>(raw)
            .expect_err("an impossible hunk must not decode");
        assert!(error.to_string().contains("line range"), "{error}");
    }
}

fn inventory_with(files: &[&str]) -> (TempDir, ProjectInventory) {
    let directory = TempDir::new().unwrap();
    for name in files {
        std::fs::write(directory.path().join(name), "fn present() {}\n").unwrap();
    }
    let inventory = ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
    (directory, inventory)
}

fn hunks(spans: &[(&str, &[(u32, u32)])]) -> HunkRanges {
    spans
        .iter()
        .map(|(path, ranges)| ((*path).to_string(), ranges.to_vec()))
        .collect()
}

#[test]
fn selection_presents_changed_files_the_inventory_holds() {
    let (_directory, inventory) = inventory_with(&["a.rs", "b.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)]), ("b.rs", &[(1, 1)])]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());

    assert_eq!(
        selection.presented_files(),
        &BTreeSet::from(["a.rs".to_string(), "b.rs".to_string()])
    );
    assert!(selection.skipped_files().is_empty());
}

#[test]
fn changed_files_missing_from_the_inventory_are_skipped() {
    let (_directory, inventory) = inventory_with(&["a.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)]), ("vendor.min.js", &[(1, 1)])]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());

    assert_eq!(
        selection.presented_files(),
        &BTreeSet::from(["a.rs".to_string()])
    );
    assert_eq!(
        selection.skipped_files(),
        ["vendor.min.js (absent from the analyzed project)"]
    );
    assert!(
        !selection.changed_lines().covers("vendor.min.js"),
        "a file that was never presented must not accept findings"
    );
}

#[test]
fn a_precomputed_skip_report_replaces_the_generic_reason() {
    let (_directory, inventory) = inventory_with(&["a.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)]), ("huge.bin", &[(1, 1)])]);
    let reports = BTreeMap::from([(
        "huge.bin".to_string(),
        "huge.bin (excluded by engine filters)".to_string(),
    )]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &reports);

    assert_eq!(
        selection.skipped_files(),
        ["huge.bin (excluded by engine filters)"]
    );
}

#[test]
fn a_precomputed_skip_is_ignored_when_the_file_is_actually_present() {
    let (_directory, inventory) = inventory_with(&["a.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)])]);
    let reports = BTreeMap::from([("a.rs".to_string(), "a.rs (unsafe path)".to_string())]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &reports);

    assert_eq!(
        selection.presented_files(),
        &BTreeSet::from(["a.rs".to_string()])
    );
    assert!(
        selection.skipped_files().is_empty(),
        "a file the shards really present is not skipped coverage"
    );
}

#[test]
fn a_changed_file_without_new_side_lines_is_skipped() {
    let (_directory, inventory) = inventory_with(&["a.rs", "renamed.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)]), ("renamed.rs", &[])]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());

    assert_eq!(
        selection.presented_files(),
        &BTreeSet::from(["a.rs".to_string()])
    );
    assert_eq!(
        selection.skipped_files(),
        ["renamed.rs (no changed lines on the new side)"]
    );
}

#[test]
fn an_unusable_diff_hunk_skips_the_file_instead_of_failing_the_run() {
    let (_directory, inventory) = inventory_with(&["a.rs", "broken.rs"]);
    let diff = hunks(&[("a.rs", &[(1, 1)]), ("broken.rs", &[(9, 4)])]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());

    assert_eq!(
        selection.presented_files(),
        &BTreeSet::from(["a.rs".to_string()])
    );
    assert_eq!(selection.skipped_files().len(), 1);
    assert!(
        selection.skipped_files()[0].starts_with("broken.rs (unusable diff hunk:"),
        "{:?}",
        selection.skipped_files()
    );
    assert!(!selection.changed_lines().covers("broken.rs"));
}

#[test]
fn selection_keeps_the_finding_scope_it_was_built_from() {
    let (_directory, inventory) = inventory_with(&["a.rs"]);
    let diff = hunks(&[("a.rs", &[(4, 6)])]);

    let selection = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());

    assert!(selection.changed_lines().overlaps("a.rs", range(6, 9)));
    assert!(!selection.changed_lines().overlaps("a.rs", range(7, 9)));
}
