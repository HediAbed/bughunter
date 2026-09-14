use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

use crate::cancel::CancelToken;
use crate::config::schema::Config;
use crate::config::schema::MIN_CONTEXT_TOKENS;
use crate::engine::{Engine, ProjectInventory};
use crate::errors::{BugHunterError, LlmError, RepoMapError};
use crate::repomap::{
    self,
    shard::{Shard, estimate_file_tokens, partition_into_shards},
};
use crate::report::limits::{BoundedDiagnostics, path_diagnostic};
use crate::report::{FailedShard, Finding, FindingCounter, ScanCompleteness, ScanStatus};
use crate::tui::Reporter;

use super::agent::{AgentLoop, MAX_FINDING_BYTES_PER_RUN, MAX_FINDINGS_PER_RUN};
use super::client::LlmBackend;
use super::review_scope::ReviewSelection;
use super::tool_exec::ToolExecutor;

const SHARD_CONTENT_CONTEXT_PERCENT: u32 = 40;
const MIN_SHARD_BUDGET_TOKENS: u32 = MIN_CONTEXT_TOKENS / 100 * SHARD_CONTENT_CONTEXT_PERCENT;
const MAX_SHARDS: usize = 50;

#[derive(Default)]
pub struct CoverageTracker {
    read_paths: Mutex<BTreeSet<String>>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, path: String) {
        self.read_paths.lock().insert(path);
    }

    pub fn read_paths(&self) -> BTreeSet<String> {
        self.read_paths.lock().clone()
    }
}

pub(crate) struct ShardedAnalysisRequest<'a> {
    pub(crate) backend: &'a dyn LlmBackend,
    pub(crate) engine: Arc<dyn Engine>,
    pub(crate) inventory: Arc<ProjectInventory>,
    pub(crate) config: &'a Config,
    pub(crate) counter: Arc<FindingCounter>,
    pub(crate) system_prompt: &'a str,
    pub(crate) reporter: &'a Reporter,
    pub(crate) review: Option<&'a ReviewSelection>,
    pub(crate) cancel: &'a CancelToken,
}

pub struct ShardedAnalysis {
    pub findings: Vec<Finding>,
    pub status: ScanStatus,
}

fn shard_content_budget(context_tokens: u32) -> u32 {
    (context_tokens / 100 * SHARD_CONTENT_CONTEXT_PERCENT).max(MIN_SHARD_BUDGET_TOKENS)
}

fn shard_eligible_tokens(shard: &Shard) -> u64 {
    shard
        .files
        .iter()
        .map(|entry| u64::from(estimate_file_tokens(entry)))
        .sum()
}

fn aborts_run(error: &LlmError) -> bool {
    matches!(error, LlmError::AuthError | LlmError::Cancelled)
}

fn repository_worker_failure(error: tokio::task::JoinError) -> LlmError {
    LlmError::AgentProtocol(format!("repository analysis worker failed: {error}"))
}

fn repository_build_failure(error: crate::errors::EngineError) -> LlmError {
    match error {
        crate::errors::EngineError::Cancelled => LlmError::Cancelled,
        error => LlmError::AgentProtocol(format!("repository analysis failed: {error}")),
    }
}

#[derive(Default)]
struct ShardOutcome {
    aggregate: Vec<Finding>,
    retained_bytes: usize,
    presented: BTreeSet<String>,
    skipped: BoundedDiagnostics,
    repo_map_omissions: BoundedDiagnostics,
    uninspected_reasons: BTreeMap<String, String>,
    failed_shards: Vec<FailedShard>,
    last_error: Option<LlmError>,
}

#[derive(Default)]
struct RetentionOverflow {
    findings: usize,
    bytes: usize,
}

impl RetentionOverflow {
    fn drop(&mut self, bytes: usize) {
        self.findings = self.findings.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn reason(&self) -> Option<String> {
        if self.findings == 0 {
            return None;
        }
        Some(format!(
            "analysis-wide finding budget exhausted: {} findings ({} bytes) from this shard were \
             not retained; the run keeps at most {MAX_FINDINGS_PER_RUN} findings and \
             {MAX_FINDING_BYTES_PER_RUN} bytes",
            self.findings, self.bytes
        ))
    }
}

impl ShardOutcome {
    fn admit(&mut self, findings: Vec<Finding>) -> Option<String> {
        let mut overflow = RetentionOverflow::default();
        for finding in findings {
            let bytes = finding.retained_bytes();
            let retained_bytes = self.retained_bytes.checked_add(bytes);
            if self.aggregate.len() >= MAX_FINDINGS_PER_RUN
                || retained_bytes.is_none_or(|total| total > MAX_FINDING_BYTES_PER_RUN)
            {
                overflow.drop(bytes);
                continue;
            }
            self.retained_bytes = retained_bytes.unwrap_or(self.retained_bytes);
            self.aggregate.push(finding);
        }
        overflow.reason()
    }

    fn record_skipped(&mut self, report: String) {
        self.skipped.record(report);
    }

    fn record_repo_map(&mut self, repo_map: &repomap::RepoMap) {
        self.presented.extend(repo_map.files.iter().cloned());
        for report in &repo_map.omitted_file_reports {
            self.repo_map_omissions.record_with(&mut || report.clone());
        }
        self.repo_map_omissions
            .omit(repo_map.omitted_file_diagnostics);
    }

    fn reconcile_repo_map_omissions(&mut self, read: &BTreeSet<String>) {
        let omissions = std::mem::take(&mut self.repo_map_omissions);
        let (reports, omitted_diagnostics) = omissions.into_entries();
        self.skipped.omit(omitted_diagnostics);
        for report in reports {
            match repomap::omitted_file_path(&report) {
                Some(path) if read.contains(path) => {
                    self.presented.insert(path.to_string());
                }
                _ => self.skipped.record(report),
            }
        }
    }

    fn record_incomplete_shard(&mut self, index: usize, paths: &[String]) {
        let reason = format!("shard {} did not complete", index + 1);
        for path in paths {
            self.uninspected_reasons
                .insert(path.clone(), reason.clone());
        }
    }

    fn into_analysis(mut self, tracker: &CoverageTracker, total_shards: usize) -> ShardedAnalysis {
        let read = tracker.read_paths();
        self.reconcile_repo_map_omissions(&read);
        let mut uninspected = BoundedDiagnostics::default();
        for path in self.presented.iter().filter(|path| !read.contains(*path)) {
            let reason = self
                .uninspected_reasons
                .get(path)
                .map(String::as_str)
                .unwrap_or("model did not inspect file");
            uninspected.record_with(&mut || path_diagnostic(path, reason));
        }
        let files_presented = u32::try_from(self.presented.len()).unwrap_or(u32::MAX);
        let never_opened = u32::try_from(uninspected.observed()).unwrap_or(u32::MAX);
        let files_inspected = files_presented.saturating_sub(never_opened);
        let processed_shards = total_shards.min(MAX_SHARDS);
        let (uninspected_files, uninspected_omissions) = uninspected.into_sorted_entries();
        let (skipped_files, skipped_omissions) = self.skipped.into_sorted_entries();
        let omitted_diagnostics = uninspected_omissions.saturating_add(skipped_omissions);

        ShardedAnalysis {
            status: ScanStatus {
                completeness: ScanCompleteness::of(
                    &self.failed_shards,
                    &skipped_files,
                    &uninspected_files,
                )
                .with_omissions(omitted_diagnostics),
                shards_total: u32::try_from(total_shards).unwrap_or(u32::MAX),
                shards_completed: u32::try_from(
                    processed_shards.saturating_sub(self.failed_shards.len()),
                )
                .unwrap_or(u32::MAX),
                failed_shards: self.failed_shards,
                files_presented,
                files_inspected,
                uninspected_files,
                skipped_files,
                omitted_diagnostics,
            },
            findings: dedupe_findings(self.aggregate),
        }
    }
}

struct ShardExecutor<'a> {
    backend: &'a dyn LlmBackend,
    engine: Arc<dyn Engine>,
    inventory: Arc<ProjectInventory>,
    config: &'a Config,
    counter: Arc<FindingCounter>,
    system_prompt: &'a str,
    reporter: &'a Reporter,
    tracker: Arc<CoverageTracker>,
    review: Option<&'a ReviewSelection>,
    cancel: &'a CancelToken,
    context_tokens: u32,
    signature_budget: u32,
    total_shards: usize,
}

impl<'a> ShardExecutor<'a> {
    fn new(
        request: ShardedAnalysisRequest<'a>,
        tracker: Arc<CoverageTracker>,
        context_tokens: u32,
        total_shards: usize,
    ) -> Self {
        Self {
            backend: request.backend,
            engine: request.engine,
            inventory: request.inventory,
            config: request.config,
            counter: request.counter,
            system_prompt: request.system_prompt,
            reporter: request.reporter,
            tracker,
            review: request.review,
            cancel: request.cancel,
            context_tokens,
            signature_budget: repomap::signature_detail_budget(context_tokens),
            total_shards,
        }
    }

    fn record_files_never_presented(&self, outcome: &mut ShardOutcome) {
        match self.review {
            Some(review) => {
                for report in review.skipped_files() {
                    outcome.record_skipped(report.clone());
                }
            }
            None => {
                for file in self.inventory.unreadable_files() {
                    outcome.record_skipped(file.report_entry());
                }
            }
        }
    }

    async fn run_shards(&self, shards: Vec<Shard>) -> Result<ShardOutcome, BugHunterError> {
        let processed_shards = shards.len().min(MAX_SHARDS);
        self.reporter.set_total_shards(processed_shards);
        let mut outcome = ShardOutcome::default();
        self.record_files_never_presented(&mut outcome);

        for (index, shard) in shards.into_iter().enumerate() {
            if index >= MAX_SHARDS {
                for path in shard.relative_paths() {
                    outcome.record_skipped(path_diagnostic(path, "shard limit reached"));
                }
                continue;
            }
            if self.cancel.is_cancelled() {
                return Err(LlmError::Cancelled.into());
            }
            self.run_shard(index, shard, &mut outcome).await?;
        }

        if outcome.failed_shards.len() == processed_shards
            && let Some(error) = outcome.last_error.take()
        {
            return Err(error.into());
        }
        Ok(outcome)
    }

    async fn run_shard(
        &self,
        index: usize,
        shard: Shard,
        outcome: &mut ShardOutcome,
    ) -> Result<(), BugHunterError> {
        let files = shard.files.len();
        let eligible_tokens = shard_eligible_tokens(&shard);
        let shard_paths: Vec<String> = shard.relative_paths().map(String::from).collect();
        self.reporter
            .shard_started(index + 1, files, eligible_tokens);

        let shard_map = self.build_shard_map(shard).await;
        self.complete_shard(
            index,
            files,
            eligible_tokens,
            shard_paths,
            shard_map,
            outcome,
        )
        .await
    }

    async fn complete_shard(
        &self,
        index: usize,
        files: usize,
        eligible_tokens: u64,
        shard_paths: Vec<String>,
        shard_map: Result<repomap::RepoMap, LlmError>,
        outcome: &mut ShardOutcome,
    ) -> Result<(), BugHunterError> {
        let shard_map = match shard_map {
            Ok(repo_map) => repo_map,
            Err(error) => {
                for path in shard_paths {
                    outcome.record_skipped(path_diagnostic(
                        &path,
                        "repository map construction failed",
                    ));
                }
                self.record_shard_failure(index, error, outcome);
                return Ok(());
            }
        };
        outcome.record_repo_map(&shard_map);

        match self
            .analyze_shard(index, files, eligible_tokens, &shard_map)
            .await
        {
            Ok(findings) => self.record_shard_success(index, findings, outcome),
            Err(error) if aborts_run(&error) => return Err(error.into()),
            Err(error) => {
                outcome.record_incomplete_shard(index, &shard_map.files);
                self.record_shard_failure(index, error, outcome);
            }
        }
        Ok(())
    }

    async fn build_shard_map(&self, shard: Shard) -> Result<repomap::RepoMap, LlmError> {
        let inventory = Arc::clone(&self.inventory);
        let engine_config = self.config.engine.clone();
        let signature_budget = self.signature_budget;
        let worker_cancel = self.cancel.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            repomap::build_repo_map_for_entries_cancellable(
                inventory.filesystem(),
                &engine_config,
                signature_budget,
                &shard.files,
                inventory.stats(),
                &worker_cancel,
            )
            .map_err(repository_build_failure)
        });
        let joined = tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
                worker.abort();
                return Err(LlmError::Cancelled);
            }
            joined = &mut worker => joined,
        };
        if self.cancel.is_cancelled() {
            return Err(LlmError::Cancelled);
        }
        joined.map_err(repository_worker_failure)?
    }

    async fn analyze_shard(
        &self,
        index: usize,
        files: usize,
        eligible_tokens: u64,
        shard_map: &repomap::RepoMap,
    ) -> Result<Vec<Finding>, LlmError> {
        info!(
            shard = index + 1,
            total = self.total_shards,
            files,
            eligible_tokens,
            tokens = shard_map.estimated_tokens,
            "analyzing shard"
        );

        let mut tools = ToolExecutor::from_inventory(
            Arc::clone(&self.engine),
            Arc::clone(&self.inventory),
            Arc::clone(&self.counter),
        )
        .with_coverage(Arc::clone(&self.tracker));
        if let Some(review) = self.review {
            tools = tools
                .with_allowed_files(review.presented_files().clone())
                .with_finding_scope(review.changed_lines().clone());
        }
        let mut agent = AgentLoop::new(
            self.backend,
            Arc::new(tools),
            self.context_tokens,
            self.config.llm.max_agent_iterations,
        )
        .with_reporter(self.reporter)
        .with_cancel(self.cancel)
        .with_time_budget(self.config.llm.max_shard_seconds);
        agent.run(self.system_prompt, &shard_map.text).await
    }

    fn record_shard_success(
        &self,
        index: usize,
        findings: Vec<Finding>,
        outcome: &mut ShardOutcome,
    ) {
        if let Some(reason) = outcome.admit(findings) {
            outcome.record_skipped(path_diagnostic("<findings>", &reason));
        }
        info!(
            shard = index + 1,
            total = self.total_shards,
            findings_so_far = outcome.aggregate.len(),
            "shard complete"
        );
        self.reporter.shard_completed();
    }

    fn record_shard_failure(&self, index: usize, error: LlmError, outcome: &mut ShardOutcome) {
        warn!(
            shard = index + 1,
            total = self.total_shards,
            error = %error,
            "shard failed; continuing with the remaining shards"
        );
        outcome.failed_shards.push(FailedShard {
            shard: (index + 1) as u32,
            error: error.to_string(),
        });
        outcome.last_error = Some(error);
        self.reporter.shard_completed();
    }
}

fn discover_shards(
    inventory: &ProjectInventory,
    only_paths: Option<&BTreeSet<String>>,
    content_budget: u32,
) -> Result<Vec<Shard>, BugHunterError> {
    let files = inventory.select_files(only_paths).into_owned();
    if files.is_empty() {
        return Err(RepoMapError::EmptyProject(
            inventory.filesystem().root().as_path().to_path_buf(),
        )
        .into());
    }
    Ok(partition_into_shards(files, content_budget))
}
pub(crate) async fn run_sharded_analysis(
    request: ShardedAnalysisRequest<'_>,
) -> Result<ShardedAnalysis, BugHunterError> {
    let context_tokens = request.config.llm.effective_context_tokens();
    let shards = discover_shards(
        &request.inventory,
        request.review.map(ReviewSelection::presented_files),
        shard_content_budget(context_tokens),
    )?;
    let total_shards = shards.len();
    info!(
        shards = total_shards,
        context_tokens, "sharding codebase for full-coverage analysis"
    );
    let tracker = Arc::new(CoverageTracker::new());
    let executor = ShardExecutor::new(request, Arc::clone(&tracker), context_tokens, total_shards);
    let outcome = executor.run_shards(shards).await?;
    let analysis = outcome.into_analysis(&tracker, total_shards);
    report_coverage(&analysis.status);
    Ok(analysis)
}

fn report_coverage(status: &ScanStatus) {
    info!(
        presented = status.files_presented,
        inspected = status.files_inspected,
        "coverage summary"
    );

    if !status.failed_shards.is_empty() {
        warn!(
            failed = ?status.failed_shards,
            "shards failed and were skipped; their files were not analyzed"
        );
    }

    if !status.skipped_files.is_empty() {
        warn!(
            count = status.skipped_files.len(),
            files = ?status.skipped_files,
            "files were never presented for review and were not analyzed"
        );
    }

    if !status.uninspected_files.is_empty() {
        warn!(
            count = status.uninspected_files.len(),
            files = ?status.uninspected_files,
            "files were presented in a shard but the model never opened them via read_file"
        );
    }
}

pub fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut index = FindingIndex::default();
    let mut kept = Vec::with_capacity(findings.len());
    for finding in findings {
        if index.holds_duplicate_of(&finding) {
            continue;
        }
        index.insert(&finding);
        kept.push(finding);
    }
    kept
}

#[derive(Default)]
struct FindingIndex {
    files: HashMap<PathBuf, FileIdentities>,
}

#[derive(Default)]
struct FileIdentities {
    by_rule: HashMap<String, LineSpans>,
    ruled_by_title: HashMap<String, LineSpans>,
    unruled_by_title: HashMap<String, LineSpans>,
}

impl FindingIndex {
    fn holds_duplicate_of(&self, finding: &Finding) -> bool {
        let Some(span) = LineSpan::of(finding) else {
            return false;
        };
        let Some(identities) = self.files.get(&finding.file) else {
            return false;
        };
        match &finding.rule {
            Some(rule) => {
                overlaps(&identities.by_rule, rule, span)
                    || overlaps(&identities.unruled_by_title, &finding.title, span)
            }
            None => {
                overlaps(&identities.unruled_by_title, &finding.title, span)
                    || overlaps(&identities.ruled_by_title, &finding.title, span)
            }
        }
    }

    fn insert(&mut self, finding: &Finding) {
        let Some(span) = LineSpan::of(finding) else {
            return;
        };
        let identities = self.files.entry(finding.file.clone()).or_default();
        match &finding.rule {
            Some(rule) => {
                record(&mut identities.by_rule, rule, span);
                record(&mut identities.ruled_by_title, &finding.title, span);
            }
            None => record(&mut identities.unruled_by_title, &finding.title, span),
        }
    }
}

fn overlaps(identities: &HashMap<String, LineSpans>, key: &str, span: LineSpan) -> bool {
    identities
        .get(key)
        .is_some_and(|spans| spans.overlaps(span))
}

fn record(identities: &mut HashMap<String, LineSpans>, key: &str, span: LineSpan) {
    if let Some(spans) = identities.get_mut(key) {
        spans.insert(span);
        return;
    }
    let mut spans = LineSpans::default();
    spans.insert(span);
    identities.insert(key.to_string(), spans);
}

#[derive(Clone, Copy)]
struct LineSpan {
    start: u32,
    end: u32,
}

impl LineSpan {
    fn of(finding: &Finding) -> Option<Self> {
        match (finding.line_start, finding.line_end) {
            (Some(first), Some(second)) => Some(Self {
                start: first.min(second),
                end: first.max(second),
            }),
            _ => None,
        }
    }
}

#[derive(Default)]
struct LineSpans(BTreeMap<u32, u32>);

impl LineSpans {
    fn overlaps(&self, span: LineSpan) -> bool {
        #[cfg(test)]
        record_span_comparison();
        self.0
            .range(..=span.end)
            .next_back()
            .is_some_and(|(_, end)| *end >= span.start)
    }

    fn insert(&mut self, span: LineSpan) {
        let mut start = span.start;
        let mut end = span.end;
        while let Some((&existing_start, &existing_end)) =
            self.0.range(..=end.saturating_add(1)).next_back()
        {
            if existing_end.saturating_add(1) < start {
                break;
            }
            start = start.min(existing_start);
            end = end.max(existing_end);
            self.0.remove(&existing_start);
        }
        self.0.insert(start, end);
    }
}

#[cfg(test)]
thread_local! {
    static SPAN_COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_span_comparison() {
    SPAN_COMPARISONS.with(|comparisons| comparisons.set(comparisons.get() + 1));
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod tests;
