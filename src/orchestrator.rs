use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crate::analysis;
use crate::config::schema::{
    AnalysisCategory, AnalysisMode, BackendConfig, Confidence, Config, OutputFormat,
};
use crate::config::{EngineConfig, ValidatedConfig};
use crate::engine::walker::UnreadableFile;
use crate::engine::{DefaultEngine, ProjectInventory};
use crate::errors::{BugHunterError, ReportError};
use crate::llm::claude_cli;
use crate::llm::client::OpenAiBackend;
use crate::llm::coverage;
use crate::llm::prompts;
use crate::llm::review_scope::ReviewSelection;
use crate::repomap::{self, RepoMap};
use crate::report::json;
use crate::report::limits::{
    BoundedDiagnostics, BoundedText, MARKDOWN_REPORT, MAX_REPORT_BYTES, path_diagnostic,
};
use crate::report::{
    Finding, FindingCounter, FindingSource, ScanCompleteness, ScanStatus, findings_above_threshold,
};
use crate::shared::{
    canonicalize_path_with_missing_leaf, sanitize_markdown_block, sanitize_markdown_code,
    sanitize_markdown_inline,
};
use crate::tui::{Reporter, Tui};
use crate::version;

const REVIEW_DIFF_CHAR_CAP: usize = 24_000;

#[derive(Debug)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub output: String,
    pub has_findings_above_threshold: bool,
    pub scan: ScanStatus,
}

struct AnalysisContext {
    engine: Arc<DefaultEngine>,
    inventory: Arc<ProjectInventory>,
    counter: Arc<FindingCounter>,
}

fn prepare_context(
    project_root: &Path,
    config: &Config,
) -> Result<AnalysisContext, BugHunterError> {
    let counter = Arc::new(FindingCounter::new());
    let engine = Arc::new(DefaultEngine::new(config.engine.clone()));
    let inventory = Arc::new(ProjectInventory::build(project_root, &config.engine)?);
    Ok(AnalysisContext {
        engine,
        inventory,
        counter,
    })
}

fn prepare_context_cancellable(
    project_root: &Path,
    config: &Config,
    cancel: &crate::cancel::CancelToken,
) -> Result<AnalysisContext, BugHunterError> {
    let counter = Arc::new(FindingCounter::new());
    let engine = Arc::new(DefaultEngine::new(config.engine.clone()));
    let inventory = Arc::new(ProjectInventory::build_cancellable(
        project_root,
        &config.engine,
        cancel,
    )?);
    Ok(AnalysisContext {
        engine,
        inventory,
        counter,
    })
}

async fn run_blocking_analysis<T>(
    action: &'static str,
    cancel: &crate::cancel::CancelToken,
    work: impl FnOnce() -> Result<T, BugHunterError> + Send + 'static,
) -> Result<T, BugHunterError>
where
    T: Send + 'static,
{
    ensure_not_cancelled(cancel)?;
    let mut worker = tokio::task::spawn_blocking(work);
    let joined = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            worker.abort();
            return Err(BugHunterError::Cancelled);
        }
        joined = &mut worker => joined,
    };
    ensure_not_cancelled(cancel)?;
    match joined {
        Ok(result) => result,
        Err(error) => Err(crate::errors::AnalysisError::WorkerFailed {
            action,
            reason: error.to_string(),
        }
        .into()),
    }
}

fn build_repo_map(
    inventory: &ProjectInventory,
    engine_config: &EngineConfig,
    context_tokens: u32,
    only_paths: Option<&std::collections::BTreeSet<String>>,
    cancel: &crate::cancel::CancelToken,
) -> Result<RepoMap, BugHunterError> {
    info!(project = %inventory.filesystem().root(), "building repo map");
    let signature_budget = repomap::signature_detail_budget(context_tokens);
    let selected_files = inventory.select_files_cancellable(only_paths, cancel)?;
    if selected_files.is_empty() {
        return Err(crate::errors::RepoMapError::EmptyProject(
            inventory.filesystem().root().as_path().to_path_buf(),
        )
        .into());
    }
    let repo_map = repomap::build_repo_map_for_entries_cancellable(
        inventory.filesystem(),
        engine_config,
        signature_budget,
        &selected_files,
        inventory.stats(),
        cancel,
    )?;
    info!(
        files = repo_map.files.len(),
        tokens = repo_map.estimated_tokens,
        "repo map built"
    );
    report_repo_map_omissions(&repo_map);
    Ok(repo_map)
}

fn report_repo_map_omissions(repo_map: &RepoMap) {
    if repo_map.omitted_files == 0 {
        return;
    }
    warn!(
        omitted = repo_map.omitted_files,
        presented = repo_map.files.len(),
        "the repo map byte budget dropped files; they are not presented for analysis"
    );
}

fn run_static_checks(
    engine: &DefaultEngine,
    inventory: &ProjectInventory,
    config: &Config,
    counter: &FindingCounter,
) -> Result<analysis::StaticAnalysis, BugHunterError> {
    info!("running static analysis checks");
    let static_analysis =
        analysis::run_static_checks_with_inventory(engine, inventory, &config.analysis, counter)?;
    info!(
        count = static_analysis.findings.len(),
        files = static_analysis.files_scanned,
        "static analysis complete"
    );
    Ok(static_analysis)
}

fn run_static_checks_cancellable(
    engine: &DefaultEngine,
    inventory: &ProjectInventory,
    config: &Config,
    counter: &FindingCounter,
    cancel: &crate::cancel::CancelToken,
) -> Result<analysis::StaticAnalysis, BugHunterError> {
    info!("running static analysis checks");
    let static_analysis = analysis::run_static_checks_with_inventory_cancellable(
        engine,
        inventory,
        &config.analysis,
        counter,
        cancel,
    )?;
    info!(
        count = static_analysis.findings.len(),
        files = static_analysis.files_scanned,
        "static analysis complete"
    );
    Ok(static_analysis)
}

pub fn run_static_analysis(
    project_root: &Path,
    config: &ValidatedConfig,
) -> Result<AnalysisResult, BugHunterError> {
    let ctx = prepare_context(project_root, config)?;
    let static_analysis = run_static_checks(&ctx.engine, &ctx.inventory, config, &ctx.counter)?;
    let scan = ScanStatus::static_scan(
        static_analysis.files_scanned,
        static_analysis.skipped_files,
        static_analysis.omitted_skipped_files,
    );
    build_result(
        static_analysis.findings,
        project_root,
        config,
        &AnalysisMode::Static.to_string(),
        scan,
    )
}

pub async fn run_analysis(
    project_root: &Path,
    backend_working_directory: Option<&Path>,
    config: &ValidatedConfig,
    state: crate::tui::SharedState,
    use_tui: bool,
    review: Option<&crate::review::ReviewScope>,
    cancel: crate::cancel::CancelToken,
) -> Result<AnalysisResult, BugHunterError> {
    let mode = config.mode();
    let reporter = Reporter::new(state.clone());
    if let Err(error) = ensure_not_cancelled(&cancel) {
        report_failed_outcome(&reporter, &error);
        return Err(error);
    }

    let owned_project_root = project_root.to_path_buf();
    let owned_config = config.clone();
    let worker_cancel = cancel.clone();
    let preparation = run_blocking_analysis("prepare project", &cancel, move || {
        let ctx = prepare_context_cancellable(&owned_project_root, &owned_config, &worker_cancel)?;
        let findings = initial_findings_cancellable(&ctx, &owned_config, mode, &worker_cancel)?;
        Ok((ctx, findings))
    })
    .await;
    let preparation = cancellation_precedes(&cancel, preparation);
    let (ctx, mut findings) = reporting_failures(&reporter, preparation)?;
    reporting_failures(&reporter, ensure_not_cancelled(&cancel))?;
    reporter.set_findings(findings.len());
    info!(backend = ?config.llm.backend, "starting AI-powered analysis");

    let system_prompt = build_analysis_prompt(config, review);
    let mut start_terminal = Tui::start;
    let tui = reporting_failures(
        &reporter,
        start_tui(use_tui, &state, &cancel, &mut start_terminal),
    )?;
    let ai_result = run_ai_analysis(AiRequest {
        config,
        backend_working_directory,
        ctx: &ctx,
        project_root,
        system_prompt: &system_prompt,
        reporter: &reporter,
        review,
        cancel: &cancel,
    })
    .await;

    let mut result = match ai_result {
        Ok(ai) => {
            info!(count = ai.findings.len(), "AI analysis complete");
            findings.extend(ai.findings);
            match ensure_not_cancelled(&cancel) {
                Ok(()) => build_result(findings, project_root, config, &mode.to_string(), ai.scan)
                    .and_then(|result| {
                        ensure_not_cancelled(&cancel)?;
                        Ok(result)
                    }),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };

    match &result {
        Ok(result) => {
            reporter.set_findings(result.findings.len());
            reporter.phase(crate::tui::Phase::Finished, "");
        }
        Err(error) => report_failed_outcome(&reporter, error),
    }
    if let Some(tui) = tui {
        result = reporting_failures(
            &reporter,
            preserve_analysis_result(result, tui.stop().await),
        );
    }
    if result.is_ok() {
        result = reporting_failures(&reporter, cancellation_precedes(&cancel, result));
    }

    result
}

fn preserve_analysis_result<T>(
    result: Result<T, BugHunterError>,
    terminal_result: std::io::Result<()>,
) -> Result<T, BugHunterError> {
    match (result, terminal_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(source)) => Err(crate::errors::AnalysisError::TerminalFailed {
            action: "restore terminal state",
            source,
        }
        .into()),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(terminal_error)) => {
            warn!(%terminal_error, "terminal cleanup also failed after analysis failure");
            Err(error)
        }
    }
}

fn report_failed_outcome(reporter: &Reporter, error: &BugHunterError) {
    let phase = match error {
        BugHunterError::Cancelled | BugHunterError::Llm(crate::errors::LlmError::Cancelled) => {
            crate::tui::Phase::Cancelled
        }
        _ => crate::tui::Phase::Failed,
    };
    reporter.phase(phase, error.to_string());
}

fn reporting_failures<T>(
    reporter: &Reporter,
    result: Result<T, BugHunterError>,
) -> Result<T, BugHunterError> {
    if let Err(error) = &result {
        report_failed_outcome(reporter, error);
    }
    result
}

fn cancellation_precedes<T>(
    cancel: &crate::cancel::CancelToken,
    result: Result<T, BugHunterError>,
) -> Result<T, BugHunterError> {
    ensure_not_cancelled(cancel)?;
    result
}

fn ensure_not_cancelled(cancel: &crate::cancel::CancelToken) -> Result<(), BugHunterError> {
    if cancel.is_cancelled() {
        return Err(BugHunterError::Cancelled);
    }
    Ok(())
}

#[cfg(test)]
fn initial_findings(
    ctx: &AnalysisContext,
    config: &Config,
    mode: AnalysisMode,
) -> Result<Vec<Finding>, BugHunterError> {
    if mode.requires_static() {
        Ok(run_static_checks(&ctx.engine, &ctx.inventory, config, &ctx.counter)?.findings)
    } else {
        Ok(Vec::new())
    }
}

fn initial_findings_cancellable(
    ctx: &AnalysisContext,
    config: &Config,
    mode: AnalysisMode,
    cancel: &crate::cancel::CancelToken,
) -> Result<Vec<Finding>, BugHunterError> {
    if mode.requires_static() {
        Ok(run_static_checks_cancellable(
            &ctx.engine,
            &ctx.inventory,
            config,
            &ctx.counter,
            cancel,
        )?
        .findings)
    } else {
        Ok(Vec::new())
    }
}

fn build_analysis_prompt(config: &Config, review: Option<&crate::review::ReviewScope>) -> String {
    let mut prompt = prompts::build_system_prompt(&config.analysis);
    if let Some(scope) = review {
        prompt.push_str("\n\n");
        prompt.push_str(&scope.prompt_section(REVIEW_DIFF_CHAR_CAP));
    }
    prompt
}

fn start_tui(
    use_tui: bool,
    state: &crate::tui::SharedState,
    cancel: &crate::cancel::CancelToken,
    start: &mut dyn FnMut(
        crate::tui::SharedState,
        crate::cancel::CancelToken,
    ) -> std::io::Result<Tui>,
) -> Result<Option<Tui>, BugHunterError> {
    if !use_tui {
        return Ok(None);
    }
    start(state.clone(), cancel.clone())
        .map(Some)
        .map_err(|source| {
            BugHunterError::Analysis(crate::errors::AnalysisError::TerminalFailed {
                action: "start",
                source,
            })
        })
}

struct AiRequest<'a> {
    config: &'a Config,
    ctx: &'a AnalysisContext,
    project_root: &'a Path,
    backend_working_directory: Option<&'a Path>,
    system_prompt: &'a str,
    reporter: &'a Reporter,
    review: Option<&'a crate::review::ReviewScope>,
    cancel: &'a crate::cancel::CancelToken,
}

struct AiAnalysis {
    findings: Vec<Finding>,
    scan: ScanStatus,
}

async fn run_ai_analysis(request: AiRequest<'_>) -> Result<AiAnalysis, BugHunterError> {
    match &request.config.llm.backend {
        BackendConfig::OpenAiCompatible { .. } => run_sharded_ai_analysis(&request).await,
        BackendConfig::ClaudeCli { .. } => run_claude_ai_analysis(&request).await,
    }
}

async fn run_sharded_ai_analysis(request: &AiRequest<'_>) -> Result<AiAnalysis, BugHunterError> {
    let backend = OpenAiBackend::new(request.config.llm.clone())?;
    let resolved = resolve_context_window(request.config, &backend, request.cancel).await?;
    request
        .reporter
        .set_model(&resolved.llm.model, resolved.llm.effective_context_tokens());
    let review = review_selection(request.review, &request.ctx.inventory);
    let sharded = coverage::run_sharded_analysis(coverage::ShardedAnalysisRequest {
        backend: &backend,
        engine: request.ctx.engine.clone(),
        inventory: Arc::clone(&request.ctx.inventory),
        config: &resolved,
        counter: Arc::clone(&request.ctx.counter),
        system_prompt: request.system_prompt,
        reporter: request.reporter,
        review: review.as_ref(),
        cancel: request.cancel,
    })
    .await?;

    Ok(AiAnalysis {
        findings: sharded.findings,
        scan: sharded.status,
    })
}

fn review_selection(
    review: Option<&crate::review::ReviewScope>,
    inventory: &ProjectInventory,
) -> Option<ReviewSelection> {
    let scope = review?;
    let mut skip_reports: std::collections::BTreeMap<String, String> = scope
        .skipped_changed_files()
        .iter()
        .map(|skipped| (skipped.path.clone(), skipped.report_entry()))
        .collect();
    skip_reports.extend(
        inventory
            .unreadable_files()
            .iter()
            .map(|file| (file.relative_path.clone(), file.report_entry())),
    );
    let hunks = scope.hunk_ranges();
    Some(ReviewSelection::from_diff(&hunks, inventory, &skip_reports))
}

async fn run_claude_ai_analysis(request: &AiRequest<'_>) -> Result<AiAnalysis, BugHunterError> {
    request.reporter.set_model(
        &request.config.llm.model,
        request.config.llm.effective_context_tokens(),
    );
    request.reporter.set_total_shards(1);
    request
        .reporter
        .phase(crate::tui::Phase::Discovering, "building repository map");

    let review = review_selection(request.review, &request.ctx.inventory);
    let inventory = Arc::clone(&request.ctx.inventory);
    let engine_config = request.config.engine.clone();
    let context_tokens = request.config.llm.effective_context_tokens();
    let only_paths = review
        .as_ref()
        .map(ReviewSelection::presented_files)
        .cloned();
    let worker_cancel = request.cancel.clone();
    let repo_map = run_blocking_analysis("build repository map", request.cancel, move || {
        build_repo_map(
            &inventory,
            &engine_config,
            context_tokens,
            only_paths.as_ref(),
            &worker_cancel,
        )
    })
    .await;
    let repo_map = cancellation_precedes(request.cancel, repo_map)?;

    request.reporter.shard_started(1, repo_map.files.len(), 0);
    request
        .reporter
        .phase(crate::tui::Phase::Querying, "claude CLI");
    request.reporter.model_request_started();
    let analysis = claude_cli::run_mcp_analysis(claude_cli::McpAnalysisRequest {
        config: &request.config.llm,
        engine_config: &request.config.engine,
        project_root: request.project_root,
        backend_working_directory: request.backend_working_directory,
        system_prompt: request.system_prompt,
        repo_map: &repo_map.text,
        finding_id_start: request.ctx.counter.peek(),
        changed_lines: review.as_ref().map(ReviewSelection::changed_lines),
        cancel: request.cancel,
    })
    .await?;
    request.reporter.add_findings(analysis.findings.len());
    request.reporter.shard_completed();
    Ok(claude_analysis(
        analysis,
        &repo_map,
        review.as_ref(),
        request.ctx.inventory.unreadable_files(),
    ))
}

fn claude_analysis(
    analysis: claude_cli::McpAnalysis,
    repo_map: &RepoMap,
    review: Option<&ReviewSelection>,
    unreadable_files: &[UnreadableFile],
) -> AiAnalysis {
    let skipped_files = match review {
        Some(review) => review.skipped_files().to_vec(),
        None => unreadable_files
            .iter()
            .map(UnreadableFile::report_entry)
            .collect(),
    };
    let scan = claude_scan_status(&analysis, repo_map, skipped_files);

    AiAnalysis {
        findings: analysis.findings,
        scan,
    }
}

fn claude_scan_status(
    analysis: &claude_cli::McpAnalysis,
    repo_map: &RepoMap,
    skipped_files: Vec<String>,
) -> ScanStatus {
    let mut presented: BTreeSet<String> = repo_map.files.iter().cloned().collect();
    let mut skipped = BoundedDiagnostics::default();
    for report in skipped_files {
        skipped.record(report);
    }
    for report in &repo_map.omitted_file_reports {
        match repomap::omitted_file_path(report) {
            Some(path) if analysis.inspected_files.contains(path) => {
                presented.insert(path.to_string());
            }
            _ => skipped.record_with(&mut || report.clone()),
        }
    }

    let mut uninspected = BoundedDiagnostics::default();
    for path in presented
        .iter()
        .filter(|path| !analysis.inspected_files.contains(*path))
    {
        uninspected.record_with(&mut || path_diagnostic(path, "model did not inspect file"));
    }

    let files_presented = u32::try_from(presented.len()).unwrap_or(u32::MAX);
    let never_opened = u32::try_from(uninspected.observed()).unwrap_or(u32::MAX);
    let files_inspected = files_presented.saturating_sub(never_opened);
    let (uninspected_files, uninspected_omissions) = uninspected.into_sorted_entries();
    let (skipped_files, skipped_omissions) = skipped.into_sorted_entries();
    let omitted_diagnostics = uninspected_omissions
        .saturating_add(skipped_omissions)
        .saturating_add(repo_map.omitted_file_diagnostics);

    ScanStatus {
        completeness: ScanCompleteness::of(&[], &skipped_files, &uninspected_files)
            .with_omissions(omitted_diagnostics),
        shards_total: 1,
        shards_completed: u32::from(files_inspected > 0),
        failed_shards: Vec::new(),
        files_presented,
        files_inspected,
        uninspected_files,
        skipped_files,
        omitted_diagnostics,
    }
}

async fn resolve_context_window(
    config: &Config,
    backend: &OpenAiBackend,
    cancel: &crate::cancel::CancelToken,
) -> Result<Config, BugHunterError> {
    ensure_not_cancelled(cancel)?;
    if config.llm.max_context_tokens != 0 {
        return Ok(config.clone());
    }
    let mut resolved = config.clone();
    let detected = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(BugHunterError::Cancelled),
        detected = backend.detect_context_window() => detected,
    };
    match detected {
        Some(window) => {
            info!(window, model = %config.llm.model, "using provider-reported context window");
            resolved.llm.max_context_tokens = window;
        }
        None => info!(
            window = config.llm.effective_context_tokens(),
            model = %config.llm.model,
            "provider did not report a context window; using configured fallback"
        ),
    }
    Ok(resolved)
}

fn build_result(
    findings: Vec<Finding>,
    project_root: &Path,
    config: &Config,
    mode: &str,
    scan: ScanStatus,
) -> Result<AnalysisResult, BugHunterError> {
    let findings = finalize_findings(
        findings,
        project_root,
        config.general.min_confidence,
        &config.analysis.categories,
    );
    let has_findings_above_threshold =
        findings_above_threshold(&findings, config.general.fail_severity);
    let output = render_output(
        &findings,
        project_root,
        &config.general.output_format,
        mode,
        &scan,
    )?;

    Ok(AnalysisResult {
        findings,
        output,
        has_findings_above_threshold,
        scan,
    })
}

fn finalize_findings(
    findings: Vec<Finding>,
    project_root: &Path,
    min_confidence: Confidence,
    enabled_categories: &[AnalysisCategory],
) -> Vec<Finding> {
    let canonical_root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let mut candidates: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| {
            finding.confidence >= min_confidence && enabled_categories.contains(&finding.category)
        })
        .collect();
    for finding in &mut candidates {
        normalize_finding_path(finding, &canonical_root);
    }
    candidates.sort_unstable_by(compare_findings);

    let mut finalized: Vec<Finding> = Vec::with_capacity(candidates.len());
    for finding in candidates {
        if let Some(existing) = finalized
            .iter_mut()
            .find(|existing| is_cross_pipeline_duplicate(existing, &finding))
        {
            merge_duplicate(existing, finding);
        } else {
            finalized.push(finding);
        }
    }
    finalized.sort_unstable_by(compare_findings);
    for (index, finding) in finalized.iter_mut().enumerate() {
        finding.assign_report_sequence(index + 1);
    }
    finalized
}

fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    right
        .severity
        .cmp(&left.severity)
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| {
            finding_category_order(left.category).cmp(&finding_category_order(right.category))
        })
        .then_with(|| left.file.cmp(&right.file))
        .then_with(|| {
            left.line_start
                .unwrap_or(u32::MAX)
                .cmp(&right.line_start.unwrap_or(u32::MAX))
        })
        .then_with(|| {
            left.line_end
                .unwrap_or(u32::MAX)
                .cmp(&right.line_end.unwrap_or(u32::MAX))
        })
        .then_with(|| finding_source_order(left.source).cmp(&finding_source_order(right.source)))
        .then_with(|| left.rule.cmp(&right.rule))
        .then_with(|| left.title.cmp(&right.title))
        .then_with(|| left.description.cmp(&right.description))
        .then_with(|| left.code_snippet.cmp(&right.code_snippet))
        .then_with(|| left.suggestion.cmp(&right.suggestion))
}

fn finding_category_order(category: AnalysisCategory) -> u8 {
    match category {
        AnalysisCategory::Bug => 0,
        AnalysisCategory::Quality => 1,
        AnalysisCategory::Solid => 2,
        AnalysisCategory::Vulnerability => 3,
    }
}

fn finding_source_order(source: FindingSource) -> u8 {
    match source {
        FindingSource::Static => 0,
        FindingSource::Ai => 1,
    }
}

fn normalize_finding_path(finding: &mut Finding, canonical_root: &Path) {
    let candidate = if finding.file.is_absolute() {
        finding.file.clone()
    } else {
        canonical_root.join(&finding.file)
    };
    if let Ok(resolved_file) = canonicalize_path_with_missing_leaf(&candidate)
        && let Ok(relative) = resolved_file.strip_prefix(canonical_root)
    {
        finding.file = relative.to_path_buf();
    }
}

fn is_cross_pipeline_duplicate(existing: &Finding, candidate: &Finding) -> bool {
    existing.source != candidate.source
        && existing.category == candidate.category
        && existing.file == candidate.file
        && same_rule_identity(existing, candidate)
        && line_ranges_overlap(existing, candidate)
}

fn same_rule_identity(left: &Finding, right: &Finding) -> bool {
    match (left.rule.as_deref(), right.rule.as_deref()) {
        (Some(left_rule), Some(right_rule)) => {
            normalized_rule_chars(left_rule).eq(normalized_rule_chars(right_rule))
        }
        _ => false,
    }
}

fn normalized_rule_chars(rule: &str) -> impl Iterator<Item = char> + '_ {
    rule.rsplit('.')
        .next()
        .unwrap_or(rule)
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
}

fn line_ranges_overlap(left: &Finding, right: &Finding) -> bool {
    match (
        left.line_start,
        left.line_end,
        right.line_start,
        right.line_end,
    ) {
        (Some(left_start), Some(left_end), Some(right_start), Some(right_end)) => {
            left_start <= right_end && right_start <= left_end
        }
        _ => false,
    }
}

fn merge_duplicate(existing: &mut Finding, mut duplicate: Finding) {
    if existing.source == FindingSource::Ai && duplicate.source == FindingSource::Static {
        std::mem::swap(existing, &mut duplicate);
    }
    existing.severity = existing.severity.max(duplicate.severity);
    existing.confidence = existing.confidence.max(duplicate.confidence);
    if existing.code_snippet.is_none() {
        existing.code_snippet = duplicate.code_snippet;
    }
    if existing.suggestion.is_none() {
        existing.suggestion = duplicate.suggestion;
    }
}

fn render_output(
    findings: &[Finding],
    project_root: &Path,
    format: &OutputFormat,
    mode: &str,
    scan: &ScanStatus,
) -> Result<String, BugHunterError> {
    match format {
        OutputFormat::Json => json::render(version::VERSION, project_root, findings, mode, scan)
            .map_err(BugHunterError::Report),
        OutputFormat::Md => render_markdown_summary(findings, scan).map_err(BugHunterError::Report),
    }
}

pub(crate) fn render_markdown_summary(
    findings: &[Finding],
    scan: &ScanStatus,
) -> Result<String, ReportError> {
    render_markdown_summary_within(findings, scan, MAX_REPORT_BYTES)
}

pub(crate) fn render_markdown_summary_within(
    findings: &[Finding],
    scan: &ScanStatus,
    limit_bytes: usize,
) -> Result<String, ReportError> {
    let mut output = BoundedText::new(MARKDOWN_REPORT, limit_bytes);
    output.push_fmt(format_args!(
        "# BugHunter Analysis Report\n\n**Findings:** {}\n\n",
        findings.len()
    ))?;

    if findings.is_empty() {
        output.push("No issues found.\n\n")?;
    }

    for finding in findings {
        append_markdown_finding(&mut output, finding)?;
    }

    append_markdown_coverage(&mut output, scan)?;
    Ok(output.into_string())
}

fn append_markdown_finding(output: &mut BoundedText, finding: &Finding) -> Result<(), ReportError> {
    output.push_fmt(format_args!(
        "## [{severity}] {title}\n\n",
        severity = finding.severity,
        title = sanitize_markdown_inline(&finding.title),
    ))?;
    output.push_fmt(format_args!(
        "**ID:** {}\n**Category:** {}\n**Confidence:** {}\n**Source:** {}\n**File:** {}\n",
        sanitize_markdown_inline(&finding.id),
        finding.category,
        finding.confidence,
        finding.source,
        sanitize_markdown_inline(&finding.file.display().to_string())
    ))?;
    if let (Some(start), Some(end)) = (finding.line_start, finding.line_end) {
        output.push_fmt(format_args!("**Lines:** {start}-{end}\n"))?;
    }
    if let Some(rule) = &finding.rule {
        let sanitized_rule = sanitize_markdown_inline(rule);
        output.push_fmt(format_args!("**Rule:** {sanitized_rule}\n"))?;
    }
    output.push_fmt(format_args!(
        "\n{}\n\n",
        sanitize_markdown_block(&finding.description)
    ))?;
    if let Some(snippet) = &finding.code_snippet {
        append_markdown_code(output, snippet)?;
    }
    if let Some(suggestion) = &finding.suggestion {
        output.push_fmt(format_args!(
            "**Suggestion:** {}\n\n",
            sanitize_markdown_block(suggestion)
        ))?;
    }
    output.push("---\n\n")
}

fn append_markdown_code(output: &mut BoundedText, snippet: &str) -> Result<(), ReportError> {
    let snippet = sanitize_markdown_code(snippet);
    let fence = markdown_code_fence(&snippet);
    output.push("**Code:**\n\n")?;
    output.push(&fence)?;
    output.push("\n")?;
    output.push(&snippet)?;
    if !snippet.ends_with('\n') {
        output.push("\n")?;
    }
    output.push(&fence)?;
    output.push("\n\n")
}

fn markdown_code_fence(snippet: &str) -> String {
    let backtick_length = longest_character_run(snippet, '`').saturating_add(1).max(3);
    let tilde_length = longest_character_run(snippet, '~').saturating_add(1).max(3);
    if backtick_length <= tilde_length {
        "`".repeat(backtick_length)
    } else {
        "~".repeat(tilde_length)
    }
}

fn longest_character_run(value: &str, delimiter: char) -> usize {
    value
        .chars()
        .fold((0, 0), |(longest, current), character| {
            let current = if character == delimiter {
                current + 1
            } else {
                0
            };
            (longest.max(current), current)
        })
        .0
}

fn append_markdown_coverage(
    output: &mut BoundedText,
    scan: &ScanStatus,
) -> Result<(), ReportError> {
    output.push_fmt(format_args!(
        "## Coverage\n\n**Completeness:** {}\n",
        scan.completeness
    ))?;

    if scan.shards_total > 0 {
        output.push_fmt(format_args!(
            "**Shards:** {}/{}\n",
            scan.shards_completed, scan.shards_total
        ))?;
    }
    output.push_fmt(format_args!(
        "**Files inspected:** {}/{}\n",
        scan.files_inspected, scan.files_presented
    ))?;

    if !scan.failed_shards.is_empty() {
        output.push("\n**Failed shards:**\n\n")?;
        for failed in &scan.failed_shards {
            output.push_fmt(format_args!(
                "- shard {}: {}\n",
                failed.shard,
                sanitize_markdown_inline(&failed.error)
            ))?;
        }
    }

    append_markdown_file_entries(output, "Files never presented", &scan.skipped_files)?;
    append_markdown_file_entries(
        output,
        "Files presented but not inspected",
        &scan.uninspected_files,
    )?;

    if scan.omitted_diagnostics > 0 {
        output.push_fmt(format_args!(
            "\n**Coverage entries omitted:** {}\n",
            scan.omitted_diagnostics
        ))?;
    }

    Ok(())
}

fn append_markdown_file_entries(
    output: &mut BoundedText,
    label: &str,
    entries: &[String],
) -> Result<(), ReportError> {
    if entries.is_empty() {
        return Ok(());
    }
    output.push_fmt(format_args!("\n**{label}:** {}\n\n", entries.len()))?;
    for entry in entries {
        output.push_fmt(format_args!("- {}\n", sanitize_markdown_inline(entry)))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "orchestrator_tests.rs"]
mod tests;
