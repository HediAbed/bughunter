pub mod builder;
pub mod shard;

pub use builder::build_repo_map_for_entries_cancellable;

const SIGNATURE_BUDGET_CONTEXT_PERCENT: u32 = 15;
const MIN_SIGNATURE_BUDGET_TOKENS: u32 = 8_000;
const OMITTED_FILE_REPORT_SUFFIX: &str = " (repo map byte budget exhausted)";

pub(crate) fn omitted_file_report(relative_path: &str) -> String {
    format!("{relative_path}{OMITTED_FILE_REPORT_SUFFIX}")
}

pub(crate) fn omitted_file_path(report: &str) -> Option<&str> {
    report.strip_suffix(OMITTED_FILE_REPORT_SUFFIX)
}

pub fn signature_detail_budget(context_tokens: u32) -> u32 {
    let fraction = context_tokens / 100 * SIGNATURE_BUDGET_CONTEXT_PERCENT;
    fraction.max(MIN_SIGNATURE_BUDGET_TOKENS)
}

pub(crate) fn parent_dir(relative_path: &str) -> &str {
    match relative_path.rfind('/') {
        Some(pos) => &relative_path[..pos],
        None => "",
    }
}

#[derive(Debug, Clone)]
pub struct RepoMap {
    pub text: String,
    pub files: Vec<String>,
    pub estimated_tokens: u32,
    pub omitted_files: u32,
    pub omitted_file_reports: Vec<String>,
    pub omitted_file_diagnostics: u32,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn budget_scales_with_context_window() {
        assert_eq!(signature_detail_budget(200_000), 30_000);
        assert_eq!(signature_detail_budget(1_000_000), 150_000);
    }

    #[test]
    fn budget_respects_floor_for_small_windows() {
        assert_eq!(signature_detail_budget(10_000), MIN_SIGNATURE_BUDGET_TOKENS);
        assert_eq!(signature_detail_budget(0), MIN_SIGNATURE_BUDGET_TOKENS);
    }

    #[test]
    fn parent_directory_handles_nested_and_root_files() {
        assert_eq!(parent_dir("src/nested/main.rs"), "src/nested");
        assert_eq!(parent_dir("main.rs"), "");
    }

    #[test]
    fn omitted_file_reports_round_trip_the_path() {
        let report = omitted_file_report("src/a (copy).rs");

        assert_eq!(omitted_file_path(&report), Some("src/a (copy).rs"));
        assert_eq!(omitted_file_path("src/a.rs (another reason)"), None);
    }
}
