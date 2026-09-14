#![no_main]

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Component, Path, PathBuf};

use bughunter::ReviewError;
use bughunter::fuzzing::{ArchiveLimits, extract_zip_archive};
use libfuzzer_sys::fuzz_target;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MAX_INPUT_BYTES: usize = 8192;
const MAX_SPEC_ENTRIES: usize = 24;
const MAX_SMALL_ENTRY_BYTES: usize = 512;
const COMPRESSIBLE_ENTRY_BYTES: usize = 1024 * 1024 + 1;
const LIMIT_PRESETS: u8 = 7;
const SANDBOX_HOMES: [&str; 2] = ["a", "b"];
const GUARD_LEVELS: usize = 4;
const GUARD_DIR_PREFIX: &str = "guard";
const ARCHIVE_FILE: &str = "input.zip";
const DESTINATION_DIR: &str = "dest";
const CANARY_DIR: &str = "canary";
const CANARY_FILE: &str = "untouched";
const CANARY_BYTES: &[u8] = b"untouched";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    let selector = *selector;
    let limits = bounded_limits(selector >> 1);
    let Some(archive) = archive_bytes(selector & 1 == 1, body) else {
        return;
    };

    let sandbox = tempfile::tempdir().expect("temporary directory");
    let canary = sandbox.path().join(CANARY_DIR);
    std::fs::create_dir(&canary).expect("canary directory");
    std::fs::write(canary.join(CANARY_FILE), CANARY_BYTES).expect("canary file");

    let sites = SANDBOX_HOMES.map(|home| ExtractionSite::prepare(sandbox.path(), home, &archive));
    let guarded = guarded_snapshot(sandbox.path(), &sites);

    let [first_site, second_site] = &sites;
    let first = first_site.extract(limits);
    let second = second_site.extract(limits);

    assert_eq!(
        first.report, second.report,
        "extraction outcome is not deterministic"
    );
    assert_eq!(
        first.tree, second.tree,
        "extracted tree is not deterministic"
    );
    assert_eq!(
        guarded,
        guarded_snapshot(sandbox.path(), &sites),
        "extraction changed the sandbox outside the destination"
    );
});

type SandboxTree = BTreeMap<PathBuf, Option<Vec<u8>>>;

struct Extraction {
    report: String,
    tree: SandboxTree,
}

struct ExtractionSite {
    home: PathBuf,
    archive: PathBuf,
    destination: PathBuf,
}

impl ExtractionSite {
    fn prepare(sandbox: &Path, home_name: &str, archive: &[u8]) -> Self {
        let home = sandbox.join(home_name);
        let destination = guarded_destination(&home);
        let archive_path = home.join(ARCHIVE_FILE);
        std::fs::create_dir_all(&destination).expect("destination directory");
        std::fs::write(&archive_path, archive).expect("archive file");
        Self {
            home,
            archive: archive_path,
            destination,
        }
    }

    fn extract(&self, limits: ArchiveLimits) -> Extraction {
        let outcome = extract_zip_archive(&self.archive, &self.destination, limits);
        let tree = collect_tree(&self.destination, limits);
        let report = match outcome {
            Ok(root) => {
                let root_name = archive_root_name(&self.destination, &root);
                assert_every_entry_is_under_root(&tree, &root_name);
                format!("ok {root_name}")
            }
            Err(error) => {
                assert!(
                    matches!(error, ReviewError::Archive(_) | ReviewError::Io { .. }),
                    "extraction returned an unexpected error variant: {error:?}"
                );
                let message = error.to_string();
                assert!(!message.is_empty(), "extraction error message is empty");
                format!(
                    "err {}",
                    message.replace(self.home.to_string_lossy().as_ref(), "")
                )
            }
        };

        Extraction { report, tree }
    }
}

fn guarded_destination(home: &Path) -> PathBuf {
    let mut destination = home.to_path_buf();
    for level in 0..GUARD_LEVELS {
        destination.push(format!("{GUARD_DIR_PREFIX}{level}"));
    }
    destination.push(DESTINATION_DIR);
    destination
}

fn guarded_snapshot(sandbox: &Path, sites: &[ExtractionSite]) -> SandboxTree {
    let mut snapshot = SandboxTree::new();
    let mut pending = vec![sandbox.to_path_buf()];

    while let Some(directory) = pending.pop() {
        for child in std::fs::read_dir(&directory).expect("sandbox directory") {
            let path = child.expect("sandbox entry").path();
            let relative = path
                .strip_prefix(sandbox)
                .expect("sandbox entry is outside the sandbox")
                .to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).expect("sandbox entry metadata");
            if metadata.is_dir() {
                if sites.iter().all(|site| site.destination != path) {
                    pending.push(path);
                }
                snapshot.insert(relative, None);
                continue;
            }
            assert!(
                metadata.is_file(),
                "the sandbox gained a special file outside the destination: {}",
                relative.display()
            );
            snapshot.insert(relative, Some(std::fs::read(&path).expect("sandbox file")));
        }
    }

    snapshot
}

fn archive_root_name(destination: &Path, root: &Path) -> String {
    let relative = root
        .strip_prefix(destination)
        .expect("archive root is outside the destination");
    let mut components = relative.components();
    let Some(Component::Normal(name)) = components.next() else {
        panic!(
            "archive root is not a normal path component: {}",
            relative.display()
        );
    };
    assert!(
        components.next().is_none(),
        "archive root is not a single path component: {}",
        relative.display()
    );
    name.to_string_lossy().into_owned()
}

fn assert_every_entry_is_under_root(tree: &SandboxTree, root_name: &str) {
    let root = Path::new(root_name);
    assert!(
        tree.contains_key(root),
        "successful extraction did not create the {root_name} root"
    );
    for path in tree.keys() {
        assert!(
            path.starts_with(root),
            "successful extraction created {} outside the {root_name} root",
            path.display()
        );
    }
}

fn collect_tree(destination: &Path, limits: ArchiveLimits) -> SandboxTree {
    let mut tree = SandboxTree::new();
    let mut extracted_bytes = 0u64;
    let mut pending = vec![destination.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let Ok(children) = std::fs::read_dir(&directory) else {
            continue;
        };
        for child in children {
            let path = child.expect("directory entry").path();
            let relative = path
                .strip_prefix(destination)
                .expect("extracted path is outside the destination")
                .to_path_buf();
            assert_normalized_relative_path(&relative);

            let metadata = std::fs::symlink_metadata(&path).expect("extracted entry metadata");
            assert!(
                !metadata.file_type().is_symlink(),
                "extraction created a symbolic link: {}",
                relative.display()
            );
            if metadata.is_dir() {
                pending.push(path);
                tree.insert(relative, None);
                continue;
            }
            assert!(
                metadata.is_file(),
                "extraction created a special file: {}",
                relative.display()
            );
            assert!(
                metadata.len() <= limits.max_entry_bytes,
                "{} is larger than the {} byte per-entry limit",
                relative.display(),
                limits.max_entry_bytes
            );
            extracted_bytes += metadata.len();
            assert!(
                extracted_bytes <= limits.max_extracted_bytes,
                "extraction wrote more than the {} byte extracted limit",
                limits.max_extracted_bytes
            );
            tree.insert(
                relative,
                Some(std::fs::read(&path).expect("extracted file")),
            );
        }
    }

    tree
}

fn assert_normalized_relative_path(relative: &Path) {
    for component in relative.components() {
        let Component::Normal(part) = component else {
            panic!(
                "extracted path is not a normalized relative path: {}",
                relative.display()
            );
        };
        assert!(
            !part.to_string_lossy().contains('\\'),
            "extracted path contains a backslash: {}",
            relative.display()
        );
    }
}

fn bounded_limits(selector: u8) -> ArchiveLimits {
    let base = ArchiveLimits {
        max_archive_bytes: 4 * 1024 * 1024,
        max_entries: 64,
        max_extracted_bytes: 4 * 1024 * 1024,
        max_entry_bytes: 2 * 1024 * 1024,
        max_path_depth: 8,
        max_compression_ratio: 1000,
        ..ArchiveLimits::default()
    };
    match selector % LIMIT_PRESETS {
        0 => base,
        1 => ArchiveLimits {
            max_entries: 1,
            ..base
        },
        2 => ArchiveLimits {
            max_extracted_bytes: 8,
            ..base
        },
        3 => ArchiveLimits {
            max_entry_bytes: 4,
            ..base
        },
        4 => ArchiveLimits {
            max_path_depth: 1,
            ..base
        },
        5 => ArchiveLimits {
            max_archive_bytes: 64,
            ..base
        },
        _ => ArchiveLimits {
            max_compression_ratio: 2,
            ..base
        },
    }
}

fn archive_bytes(raw: bool, body: &[u8]) -> Option<Vec<u8>> {
    if raw {
        return Some(body.to_vec());
    }
    synthesize_archive(&String::from_utf8_lossy(body))
}

fn synthesize_archive(spec: &str) -> Option<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let mut compressible_entries = 0usize;
    for line in spec.lines().take(MAX_SPEC_ENTRIES) {
        let Some(entry) = EntrySpec::parse(line, &mut compressible_entries) else {
            continue;
        };
        entry.write_into(&mut writer)?;
    }
    Some(writer.finish().ok()?.into_inner())
}

enum Payload {
    Regular(usize),
    Directory,
    Symlink(String),
    HighlyCompressible,
}

struct EntrySpec {
    name: String,
    mode: Option<u32>,
    payload: Payload,
}

impl EntrySpec {
    fn parse(line: &str, compressible_entries: &mut usize) -> Option<Self> {
        let mut fields = line.splitn(4, ':');
        let kind = fields.next()?;
        let mode = fields.next()?;
        let detail = fields.next()?;
        let name = fields.next()?;
        if name.is_empty() {
            return None;
        }

        let mode = if mode.is_empty() {
            None
        } else {
            Some(u32::from_str_radix(mode, 8).ok()?)
        };

        let payload = match kind {
            "f" => Payload::Regular(
                detail
                    .parse::<usize>()
                    .unwrap_or_default()
                    .min(MAX_SMALL_ENTRY_BYTES),
            ),
            "d" => Payload::Directory,
            "l" => Payload::Symlink(detail.to_string()),
            "z" if *compressible_entries == 0 => {
                *compressible_entries += 1;
                Payload::HighlyCompressible
            }
            _ => return None,
        };

        Some(Self {
            name: name.to_string(),
            mode,
            payload,
        })
    }

    fn write_into(&self, writer: &mut ZipWriter<Cursor<Vec<u8>>>) -> Option<()> {
        let options = match self.mode {
            Some(mode) => SimpleFileOptions::default().unix_permissions(mode),
            None => SimpleFileOptions::default(),
        };
        match &self.payload {
            Payload::Directory => writer.add_directory(self.name.as_str(), options).ok(),
            Payload::Symlink(target) => writer
                .add_symlink(self.name.as_str(), target.as_str(), options)
                .ok(),
            Payload::Regular(size) => {
                writer
                    .start_file(
                        self.name.as_str(),
                        options.compression_method(CompressionMethod::Stored),
                    )
                    .ok()?;
                writer.write_all(&vec![b'x'; *size]).ok()
            }
            Payload::HighlyCompressible => {
                writer
                    .start_file(
                        self.name.as_str(),
                        options.compression_method(CompressionMethod::Deflated),
                    )
                    .ok()?;
                writer.write_all(&vec![0u8; COMPRESSIBLE_ENTRY_BYTES]).ok()
            }
        }
    }
}
