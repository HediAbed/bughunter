use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::domain::{LineRange, LineRangeError};
use crate::engine::ProjectInventory;

type HunkRanges = BTreeMap<String, Vec<(u32, u32)>>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HunkRanges", into = "HunkRanges")]
pub struct ChangedLines {
    hunks: BTreeMap<String, Vec<LineRange>>,
}

impl ChangedLines {
    pub fn covers(&self, path: &str) -> bool {
        self.hunks.contains_key(path)
    }

    pub fn overlaps(&self, path: &str, range: LineRange) -> bool {
        self.hunks.get(path).is_some_and(|hunks| {
            hunks
                .iter()
                .any(|hunk| hunk.start() <= range.end() && range.start() <= hunk.end())
        })
    }

    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.hunks.keys().map(String::as_str)
    }
}

impl TryFrom<HunkRanges> for ChangedLines {
    type Error = LineRangeError;

    fn try_from(ranges: HunkRanges) -> Result<Self, Self::Error> {
        ranges
            .into_iter()
            .map(|(path, spans)| {
                spans
                    .into_iter()
                    .map(|(start, end)| LineRange::new(start, end))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|hunks| (path, hunks))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(|hunks| Self { hunks })
    }
}

impl From<ChangedLines> for HunkRanges {
    fn from(changed: ChangedLines) -> Self {
        changed
            .hunks
            .into_iter()
            .map(|(path, hunks)| {
                let spans = hunks
                    .iter()
                    .map(|hunk| (hunk.start(), hunk.end()))
                    .collect();
                (path, spans)
            })
            .collect()
    }
}

pub struct ReviewSelection {
    presented_files: BTreeSet<String>,
    changed_lines: ChangedLines,
    skipped_files: Vec<String>,
}

impl ReviewSelection {
    pub fn from_diff(
        hunks: &HunkRanges,
        inventory: &ProjectInventory,
        skip_reports: &BTreeMap<String, String>,
    ) -> Self {
        let available: BTreeSet<&str> = inventory
            .files()
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        let mut reviewable = BTreeMap::new();
        let mut presented_files = BTreeSet::new();
        let mut skipped_files = Vec::new();
        for (path, spans) in hunks {
            match classify_changed_file(path, spans, &available, skip_reports) {
                Ok(ranges) => {
                    presented_files.insert(path.clone());
                    reviewable.insert(path.clone(), ranges);
                }
                Err(report) => skipped_files.push(report),
            }
        }
        Self {
            presented_files,
            changed_lines: ChangedLines { hunks: reviewable },
            skipped_files,
        }
    }

    pub fn presented_files(&self) -> &BTreeSet<String> {
        &self.presented_files
    }

    pub fn changed_lines(&self) -> &ChangedLines {
        &self.changed_lines
    }

    pub fn skipped_files(&self) -> &[String] {
        &self.skipped_files
    }
}

fn classify_changed_file(
    path: &str,
    spans: &[(u32, u32)],
    available: &BTreeSet<&str>,
    skip_reports: &BTreeMap<String, String>,
) -> Result<Vec<LineRange>, String> {
    if spans.is_empty() {
        return Err(format!("{path} (no changed lines on the new side)"));
    }
    let ranges = spans
        .iter()
        .map(|(start, end)| LineRange::new(*start, *end))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{path} (unusable diff hunk: {error})"))?;
    if !available.contains(path) {
        return Err(skip_reports
            .get(path)
            .cloned()
            .unwrap_or_else(|| format!("{path} (absent from the analyzed project)")));
    }
    Ok(ranges)
}

#[cfg(test)]
#[path = "review_scope_tests.rs"]
mod tests;
