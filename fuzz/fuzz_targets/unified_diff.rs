#![no_main]

use std::collections::BTreeMap;

use bughunter::fuzzing::{DiffLimits, parse_unified_diff};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const APPENDED_BLOCK: &str = "diff --git a/appended.rs b/appended.rs\n\
                              --- a/appended.rs\n\
                              +++ b/appended.rs\n\
                              @@ -1,1 +7,3 @@\n\
                              +one\n";
const APPENDED_PATH: &str = "appended.rs";
const APPENDED_RANGE: (u32, u32) = (7, 9);
const SMALL_LIMITS: DiffLimits = DiffLimits {
    max_changed_files: 2,
    max_ranges_per_file: 2,
    max_total_ranges: 3,
    max_path_bytes: 16,
};

type ChangedRanges = BTreeMap<String, Vec<(u32, u32)>>;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let diff = String::from_utf8_lossy(data);
    let parsed = parse(&diff);
    if let Some(hunks) = &parsed {
        assert_well_formed(&diff, hunks);
    }
    assert_small_limits_bound_the_result(&diff);

    let without_carriage_returns = diff.replace('\r', "");
    let with_crlf_endings = without_carriage_returns.replace('\n', "\r\n");
    assert_eq!(
        parse(&without_carriage_returns),
        parse(&with_crlf_endings),
        "CRLF line endings changed the parsed hunks"
    );

    let terminated = terminated_diff(&diff);
    let Some(hunks) = parse(&terminated) else {
        return;
    };
    assert_well_formed(&terminated, &hunks);
    assert_eq!(
        Some(hunks.clone()),
        parse(&format!("{terminated}\n")),
        "a trailing blank line changed the parsed hunks"
    );
    assert_appending_a_block_only_adds(&terminated, &hunks);
});

fn parse(diff: &str) -> Option<ChangedRanges> {
    parse_unified_diff(diff, DiffLimits::default()).ok()
}

fn assert_small_limits_bound_the_result(diff: &str) {
    let Ok(hunks) = parse_unified_diff(diff, SMALL_LIMITS) else {
        return;
    };
    assert!(
        hunks.len() <= SMALL_LIMITS.max_changed_files,
        "a small-limit parse kept {} changed files",
        hunks.len()
    );
    let mut retained_ranges = 0usize;
    for (path, ranges) in &hunks {
        assert!(
            path.len() <= SMALL_LIMITS.max_path_bytes,
            "a small-limit parse kept the {} byte path {path:?}",
            path.len()
        );
        assert!(
            ranges.len() <= SMALL_LIMITS.max_ranges_per_file,
            "a small-limit parse kept {} ranges for {path:?}",
            ranges.len()
        );
        retained_ranges += ranges.len();
    }
    assert!(
        retained_ranges <= SMALL_LIMITS.max_total_ranges,
        "a small-limit parse kept {retained_ranges} ranges in total"
    );
}

fn terminated_diff(diff: &str) -> String {
    if diff.is_empty() || diff.ends_with('\n') {
        return diff.to_string();
    }
    format!("{diff}\n")
}

fn assert_well_formed(diff: &str, hunks: &ChangedRanges) {
    let header_lines = diff.lines().filter(|line| line.starts_with("+++ ")).count();
    let hunk_lines = diff.lines().filter(|line| line.starts_with("@@")).count();

    assert!(
        hunks.len() <= header_lines,
        "parsed {} files from {header_lines} new-side headers",
        hunks.len()
    );

    let mut parsed_ranges = 0usize;
    for (path, ranges) in hunks {
        assert!(!path.is_empty(), "parsed an empty file path");
        assert!(
            !path.contains('\t'),
            "parsed a file path containing a tab: {path:?}"
        );
        assert!(
            !path.contains('\n'),
            "parsed a file path spanning several lines: {path:?}"
        );
        for &(start, end) in ranges {
            assert!(
                start >= 1,
                "parsed a hunk range starting before line 1 for {path:?}: ({start}, {end})"
            );
            assert!(
                start <= end,
                "parsed an inverted hunk range for {path:?}: ({start}, {end})"
            );
        }
        parsed_ranges += ranges.len();
    }

    assert!(
        parsed_ranges <= hunk_lines,
        "parsed {parsed_ranges} ranges from {hunk_lines} hunk headers"
    );
}

fn assert_appending_a_block_only_adds(terminated: &str, hunks: &ChangedRanges) {
    let extended = parse(&format!("{terminated}{APPENDED_BLOCK}"))
        .unwrap_or_else(|| panic!("appending a diff block made an accepted diff invalid"));
    for (path, ranges) in hunks {
        let extended_ranges = extended
            .get(path)
            .unwrap_or_else(|| panic!("appending a diff block dropped {path:?}"));
        assert!(
            extended_ranges.starts_with(ranges),
            "appending a diff block rewrote the ranges of {path:?}: {ranges:?} became {extended_ranges:?}"
        );
    }
    let appended = extended
        .get(APPENDED_PATH)
        .unwrap_or_else(|| panic!("appended diff block went unrecognised after {terminated:?}"));
    assert_eq!(
        appended.last(),
        Some(&APPENDED_RANGE),
        "appended diff block contributed {appended:?}"
    );
}
