use crate::engine::FileEntry;
use crate::repomap::builder::{rendered_file_line_bytes, rendered_listing_bytes};
use crate::repomap::parent_dir;
use crate::shared::ESTIMATED_CHARS_PER_TOKEN;

const GROUP_SEPARATOR_BYTES: u64 = 1;

#[derive(Debug, Clone)]
pub struct Shard {
    pub files: Vec<FileEntry>,
}

impl Shard {
    pub fn relative_paths(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| f.relative_path.as_str())
    }
}

pub fn estimate_file_tokens(entry: &FileEntry) -> u32 {
    u32::try_from(estimated_file_tokens(entry)).unwrap_or(u32::MAX)
}

fn estimated_file_tokens(entry: &FileEntry) -> u64 {
    (rendered_entry_bytes(entry) / ESTIMATED_CHARS_PER_TOKEN as u64).max(1)
}

fn rendered_entry_bytes(entry: &FileEntry) -> u64 {
    let line_bytes = rendered_file_line_bytes(&entry.relative_path, entry.size_bytes) as u64;
    entry.size_bytes.saturating_add(line_bytes)
}

fn rendered_unit_bytes(files: &[FileEntry]) -> u64 {
    let content = files
        .iter()
        .map(|file| file.size_bytes)
        .fold(0u64, u64::saturating_add);
    content
        .saturating_add(rendered_listing_bytes(files) as u64)
        .saturating_add(GROUP_SEPARATOR_BYTES)
}

pub fn partition_into_shards(mut files: Vec<FileEntry>, budget_tokens: u32) -> Vec<Shard> {
    let budget = shard_budget_bytes(budget_tokens);
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let units = build_units(files, budget);
    pack_units(units, budget)
}

fn shard_budget_bytes(budget_tokens: u32) -> u64 {
    u64::from(budget_tokens.max(1)).saturating_mul(ESTIMATED_CHARS_PER_TOKEN as u64)
}

fn build_units(files: Vec<FileEntry>, budget: u64) -> Vec<Vec<FileEntry>> {
    let mut units = Vec::new();

    for group in group_by_directory(files) {
        if rendered_unit_bytes(&group) <= budget {
            units.push(group);
        } else {
            units.extend(group.into_iter().map(|file| vec![file]));
        }
    }

    units
}

fn group_by_directory(files: Vec<FileEntry>) -> Vec<Vec<FileEntry>> {
    let mut groups: Vec<Vec<FileEntry>> = Vec::new();
    let mut current: Vec<FileEntry> = Vec::new();

    for file in files {
        let directory = parent_dir(&file.relative_path);
        let continues_group = current
            .first()
            .is_some_and(|first| parent_dir(&first.relative_path) == directory);

        if !continues_group && !current.is_empty() {
            groups.push(std::mem::take(&mut current));
        }
        current.push(file);
    }

    if !current.is_empty() {
        groups.push(current);
    }

    groups
}

fn pack_units(units: Vec<Vec<FileEntry>>, budget: u64) -> Vec<Shard> {
    let mut shards = Vec::new();
    let mut current: Vec<FileEntry> = Vec::new();
    let mut current_bytes = 0u64;

    for unit in units {
        let unit_bytes = rendered_unit_bytes(&unit);
        if !current.is_empty() && current_bytes.saturating_add(unit_bytes) > budget {
            shards.push(Shard {
                files: std::mem::take(&mut current),
            });
            current_bytes = 0;
        }
        current.extend(unit);
        current_bytes = current_bytes.saturating_add(unit_bytes);
    }

    if !current.is_empty() {
        shards.push(Shard { files: current });
    }

    shards
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn entry(relative_path: &str, size_bytes: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(relative_path),
            relative_path: relative_path.to_string(),
            size_bytes,
            language: Some("rust".into()),
        }
    }

    fn shard_tokens(shard: &Shard) -> u32 {
        shard.files.iter().map(estimate_file_tokens).sum()
    }

    fn all_paths(shards: &[Shard]) -> Vec<String> {
        let mut paths: Vec<String> = shards
            .iter()
            .flat_map(|s| s.files.iter().map(|f| f.relative_path.clone()))
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn every_file_appears_in_exactly_one_shard() {
        let bytes_per_token = ESTIMATED_CHARS_PER_TOKEN as u64;
        let files = vec![
            entry("src/a.rs", 400 * bytes_per_token),
            entry("src/b.rs", 400 * bytes_per_token),
            entry("lib/c.rs", 400 * bytes_per_token),
            entry("lib/d.rs", 400 * bytes_per_token),
        ];

        let shards = partition_into_shards(files, 500);

        assert_eq!(
            all_paths(&shards),
            vec!["lib/c.rs", "lib/d.rs", "src/a.rs", "src/b.rs"]
        );
        let total: usize = shards.iter().map(|s| s.files.len()).sum();
        assert_eq!(total, 4, "no file may be duplicated or dropped");
    }

    #[test]
    fn each_shard_fits_the_budget_when_files_are_smaller_than_budget() {
        let bytes_per_token = ESTIMATED_CHARS_PER_TOKEN as u64;
        let files: Vec<FileEntry> = (0..10)
            .map(|i| entry(&format!("src/f{i}.rs"), 100 * bytes_per_token))
            .collect();

        let shards = partition_into_shards(files, 250);

        assert!(shards.len() > 1, "expected multiple shards");
        for shard in &shards {
            assert!(
                shard_tokens(shard) <= 250,
                "shard exceeded budget: {} tokens",
                shard_tokens(shard)
            );
        }
    }

    #[test]
    fn keeps_a_directory_together_when_it_fits() {
        let bytes_per_token = ESTIMATED_CHARS_PER_TOKEN as u64;
        let files = vec![
            entry("a/one.rs", 50 * bytes_per_token),
            entry("a/two.rs", 50 * bytes_per_token),
            entry("b/one.rs", 50 * bytes_per_token),
            entry("b/two.rs", 50 * bytes_per_token),
        ];

        let shards = partition_into_shards(files, 150);

        assert_eq!(shards.len(), 2);
        for shard in &shards {
            let dirs: std::collections::BTreeSet<&str> = shard
                .files
                .iter()
                .map(|f| f.relative_path.split('/').next().unwrap())
                .collect();
            assert_eq!(dirs.len(), 1, "a shard mixed directories unexpectedly");
        }
    }

    #[test]
    fn oversized_single_file_gets_its_own_shard() {
        let bytes_per_token = ESTIMATED_CHARS_PER_TOKEN as u64;
        let files = vec![
            entry("src/small.rs", 10 * bytes_per_token),
            entry("src/huge.rs", 5_000 * bytes_per_token),
        ];

        let shards = partition_into_shards(files, 500);

        assert_eq!(all_paths(&shards).len(), 2);
        assert!(
            shards
                .iter()
                .any(|s| s.files.len() == 1 && s.files[0].relative_path == "src/huge.rs"),
            "the oversized file must land in a shard by itself"
        );
    }

    #[test]
    fn token_arithmetic_saturates_without_merging_oversized_files() {
        let huge = entry("src/huge.rs", u64::MAX);
        assert_eq!(estimate_file_tokens(&huge), u32::MAX);

        let shards = partition_into_shards(vec![huge, entry("src/other.rs", u64::MAX)], u32::MAX);

        assert_eq!(shards.len(), 2);
        assert!(shards.iter().all(|shard| shard.files.len() == 1));
    }

    #[test]
    fn empty_input_produces_no_shards() {
        let shards = partition_into_shards(Vec::new(), 500);
        assert!(shards.is_empty());
    }

    #[test]
    fn a_file_estimate_covers_its_rendered_path_line() {
        let empty = entry("src/very_long_module_name.rs", 0);

        assert_eq!(
            estimate_file_tokens(&empty),
            u32::try_from(
                rendered_file_line_bytes(&empty.relative_path, 0) / ESTIMATED_CHARS_PER_TOKEN
            )
            .unwrap(),
            "a zero-byte file still costs the bytes its path line renders"
        );
    }

    #[test]
    fn every_shard_covers_the_bytes_its_map_renders() {
        let budget_tokens = 400u32;
        let budget = shard_budget_bytes(budget_tokens);
        let files: Vec<FileEntry> = (0..60u32)
            .map(|index| {
                entry(
                    &format!("crates/component_{}/src/module_{index}.rs", index % 7),
                    u64::from(index % 5) * 100,
                )
            })
            .collect();

        let shards = partition_into_shards(files, budget_tokens);

        assert!(shards.len() > 1, "expected the fixture to need sharding");
        for shard in &shards {
            let content: u64 = shard.files.iter().map(|file| file.size_bytes).sum();
            let rendered = content.saturating_add(rendered_listing_bytes(&shard.files) as u64);
            assert!(
                shard.files.len() == 1 || rendered <= budget,
                "shard of {} files renders {rendered} bytes against a {budget} byte budget",
                shard.files.len()
            );
        }
    }

    #[test]
    fn directory_grouping_survives_repeated_directory_names() {
        let files = vec![
            entry("a/one.rs", 10),
            entry("b/two.rs", 10),
            entry("a/three.rs", 10),
        ];

        let groups = group_by_directory(files);

        assert_eq!(groups.len(), 3, "a returning directory starts a new group");
        assert_eq!(groups[0][0].relative_path, "a/one.rs");
        assert_eq!(groups[2][0].relative_path, "a/three.rs");
    }

    #[test]
    fn a_zero_budget_still_partitions_every_file() {
        let shards = partition_into_shards(vec![entry("a.rs", 10), entry("b.rs", 10)], 0);

        assert_eq!(all_paths(&shards), vec!["a.rs", "b.rs"]);
        assert!(shards.iter().all(|shard| shard.files.len() == 1));
    }
}
