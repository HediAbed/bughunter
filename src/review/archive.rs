use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use super::{ReviewError, safe_truncate};

const DIRECTORY_MODE: u32 = 0o040000;
const FILE_TYPE_MASK: u32 = 0o170000;
const REGULAR_FILE_MODE: u32 = 0o100000;
const SYMBOLIC_LINK_MODE: u32 = 0o120000;

const SIGNATURE_BYTES: usize = 4;
const CLASSIC_FOOTER_SIGNATURE: [u8; SIGNATURE_BYTES] = 0x0605_4b50u32.to_le_bytes();
const ZIP64_LOCATOR_SIGNATURE: [u8; SIGNATURE_BYTES] = 0x0706_4b50u32.to_le_bytes();
const ZIP64_FOOTER_SIGNATURE: [u8; SIGNATURE_BYTES] = 0x0606_4b50u32.to_le_bytes();
const CLASSIC_FOOTER_BYTES: usize = 22;
const ZIP64_LOCATOR_BYTES: usize = 20;
const ZIP64_FOOTER_BYTES: u64 = 56;
const ZIP64_FOOTER_PREFIX_BYTES: u64 = 12;
const ZIP64_FOOTER_VERSION_BYTES: usize = 4;
const MAX_ARCHIVE_COMMENT_BYTES: usize = 65_535;
const MAX_TRAILING_METADATA_BYTES: u64 =
    (CLASSIC_FOOTER_BYTES + MAX_ARCHIVE_COMMENT_BYTES + ZIP64_LOCATOR_BYTES) as u64;
const MIN_CENTRAL_RECORD_BYTES: u64 = 46;
const FIRST_DISK: u32 = 0;
const SINGLE_DISK: u32 = 1;
const ZIP64_ENTRY_COUNT_SENTINEL: u16 = u16::MAX;
const ZIP64_OFFSET_SENTINEL: u32 = u32::MAX;
const MAX_ENTRY_NAME_BYTES: usize = 4096;
const MAX_RETAINED_PATH_BYTES: usize = 32 * 1024 * 1024;
const REPORTED_NAME_BYTES: usize = 96;

#[derive(Clone, Copy)]
pub struct ArchiveLimits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_extracted_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_path_depth: usize,
    pub max_compression_ratio: u64,
    pub max_entry_name_bytes: usize,
    pub max_retained_path_bytes: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 256 * 1024 * 1024,
            max_entries: 100_000,
            max_extracted_bytes: 1024 * 1024 * 1024,
            max_entry_bytes: 128 * 1024 * 1024,
            max_path_depth: 128,
            max_compression_ratio: 1000,
            max_entry_name_bytes: MAX_ENTRY_NAME_BYTES,
            max_retained_path_bytes: MAX_RETAINED_PATH_BYTES,
        }
    }
}

struct ArchiveEntry {
    index: usize,
    output_path: PathBuf,
    is_directory: bool,
    size: u64,
}

struct RetainedPaths {
    limit: usize,
    retained: usize,
}

impl RetainedPaths {
    fn new(limit: usize) -> Self {
        Self { limit, retained: 0 }
    }

    fn retain(&mut self, bytes: usize) -> Result<(), ReviewError> {
        let retained = self
            .retained
            .checked_add(bytes)
            .filter(|retained| *retained <= self.limit)
            .ok_or_else(|| self.limit_error())?;
        self.retained = retained;
        Ok(())
    }

    fn retain_copies(&mut self, bytes_per_copy: usize, copies: usize) -> Result<(), ReviewError> {
        let bytes = bytes_per_copy
            .checked_mul(copies)
            .ok_or_else(|| self.limit_error())?;
        self.retain(bytes)
    }

    fn limit_error(&self) -> ReviewError {
        ReviewError::Archive(format!(
            "archive paths exceed the {} byte path retention limit",
            self.limit
        ))
    }
}

pub fn extract_zip_archive(
    archive_path: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<PathBuf, ReviewError> {
    let archive_bytes = validated_archive_size(archive_path, limits.max_archive_bytes)?;
    let mut archive_file = std::fs::File::open(archive_path).map_err(|source| ReviewError::Io {
        action: "open pull request archive".to_string(),
        source,
    })?;
    preflight_declared_entries(&mut archive_file, archive_bytes, limits)?;
    let mut archive = zip::ZipArchive::new(archive_file).map_err(archive_error)?;
    let (root_name, entries) = inspect_archive(&mut archive, limits)?;
    let root = destination.join(&root_name);
    std::fs::create_dir_all(&root).map_err(|source| ReviewError::Io {
        action: "create pull request archive root".to_string(),
        source,
    })?;
    extract_entries(&mut archive, &root, &entries)?;
    Ok(root)
}

fn validated_archive_size(path: &Path, limit: u64) -> Result<u64, ReviewError> {
    let size = std::fs::metadata(path)
        .map_err(|source| ReviewError::Io {
            action: "inspect pull request archive".to_string(),
            source,
        })?
        .len();
    if size > limit {
        return Err(ReviewError::Archive(format!(
            "downloaded archive exceeds {limit} bytes"
        )));
    }
    Ok(size)
}

struct TrailingMetadata {
    start: u64,
    bytes: Vec<u8>,
}

impl TrailingMetadata {
    fn absolute(&self, window_offset: usize) -> Option<u64> {
        self.start.checked_add(u64::try_from(window_offset).ok()?)
    }
}

struct ClassicFooter {
    window_offset: usize,
    disk_number: u16,
    disk_with_central_directory: u16,
    entries_on_disk: u16,
    total_entries: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
    comment_bytes: u16,
}

impl ClassicFooter {
    fn may_declare_zip64(&self) -> bool {
        self.total_entries == ZIP64_ENTRY_COUNT_SENTINEL
            || self.central_directory_size == ZIP64_OFFSET_SENTINEL
            || self.central_directory_offset == ZIP64_OFFSET_SENTINEL
    }

    fn terminates_at(&self, window_bytes: usize) -> bool {
        self.window_offset
            .checked_add(CLASSIC_FOOTER_BYTES)
            .and_then(|end| end.checked_add(usize::from(self.comment_bytes)))
            == Some(window_bytes)
    }
}

struct Zip64Locator {
    disk_with_central_directory: u32,
    footer_offset: u64,
    total_disks: u32,
}

struct Zip64Footer {
    offset: u64,
    record_bytes: u64,
    disk_number: u32,
    disk_with_central_directory: u32,
    entries_on_disk: u64,
    total_entries: u64,
    central_directory_size: u64,
    central_directory_offset: u64,
}

struct DeclaredCentralDirectory {
    entries: u64,
    size: u64,
    offset: u64,
    footer_offset: u64,
}

struct FieldReader<'a> {
    bytes: &'a [u8],
}

impl<'a> FieldReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        self.bytes = self.bytes.get(count..)?;
        Some(())
    }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (field, rest) = self.bytes.split_at_checked(N)?;
        self.bytes = rest;
        field.try_into().ok()
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take()?))
    }
}

fn preflight_declared_entries(
    file: &mut std::fs::File,
    archive_bytes: u64,
    limits: ArchiveLimits,
) -> Result<(), ReviewError> {
    let trailer = read_trailing_metadata(file, archive_bytes)?;
    let classic = locate_classic_footer(&trailer)?;
    let zip64 = resolve_zip64_footer(file, &trailer, &classic)?;
    let declared = declared_central_directory(&trailer, &classic, zip64)?;
    enforce_declared_entry_limit(declared.entries, limits.max_entries)?;
    validate_central_directory_bounds(&declared)?;
    rewind_archive_file(file.rewind())?;
    Ok(())
}

fn rewind_archive_file(result: std::io::Result<()>) -> Result<(), ReviewError> {
    result.map_err(|source| ReviewError::Io {
        action: "rewind pull request archive".to_string(),
        source,
    })
}

fn read_trailing_metadata(
    file: &mut std::fs::File,
    archive_bytes: u64,
) -> Result<TrailingMetadata, ReviewError> {
    let start = archive_bytes.saturating_sub(MAX_TRAILING_METADATA_BYTES);
    let bytes = read_fixed_window(
        file,
        start,
        archive_bytes.saturating_sub(start),
        "read archive trailing metadata",
    )?;
    Ok(TrailingMetadata { start, bytes })
}

fn read_fixed_window(
    file: &mut std::fs::File,
    offset: u64,
    bytes: u64,
    action: &str,
) -> Result<Vec<u8>, ReviewError> {
    let bytes = addressable_window_bytes(bytes, usize::MAX)?;
    let mut window = vec![0; bytes];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut window))
        .map_err(|source| ReviewError::Io {
            action: action.to_string(),
            source,
        })?;
    Ok(window)
}

fn addressable_window_bytes(bytes: u64, max_addressable: usize) -> Result<usize, ReviewError> {
    if u128::from(bytes) > max_addressable as u128 {
        return Err(unaddressable_trailing_metadata());
    }
    Ok(bytes as usize)
}

fn locate_classic_footer(trailer: &TrailingMetadata) -> Result<ClassicFooter, ReviewError> {
    let window = trailer.bytes.as_slice();
    let Some(last_offset) = window.len().checked_sub(CLASSIC_FOOTER_BYTES) else {
        return Err(missing_classic_footer());
    };
    let mut located: Option<ClassicFooter> = None;
    for window_offset in (0..=last_offset).rev() {
        if !window
            .get(window_offset..)
            .is_some_and(|tail| tail.starts_with(&CLASSIC_FOOTER_SIGNATURE))
        {
            continue;
        }
        let Some(footer) = parse_classic_footer(window, window_offset) else {
            continue;
        };
        if !footer.terminates_at(window.len()) {
            continue;
        }
        if located.is_some() {
            return Err(ambiguous_classic_footer());
        }
        located = Some(footer);
    }
    located.ok_or_else(missing_classic_footer)
}

fn parse_classic_footer(window: &[u8], window_offset: usize) -> Option<ClassicFooter> {
    let bytes = window.get(window_offset..)?;
    if !bytes.starts_with(&CLASSIC_FOOTER_SIGNATURE) {
        return None;
    }
    let mut fields = FieldReader::new(bytes);
    fields.skip(SIGNATURE_BYTES)?;
    Some(ClassicFooter {
        window_offset,
        disk_number: fields.u16()?,
        disk_with_central_directory: fields.u16()?,
        entries_on_disk: fields.u16()?,
        total_entries: fields.u16()?,
        central_directory_size: fields.u32()?,
        central_directory_offset: fields.u32()?,
        comment_bytes: fields.u16()?,
    })
}

fn resolve_zip64_footer(
    file: &mut std::fs::File,
    trailer: &TrailingMetadata,
    classic: &ClassicFooter,
) -> Result<Option<Zip64Footer>, ReviewError> {
    if !classic.may_declare_zip64() {
        return Ok(None);
    }
    let Some(locator_window_offset) = classic.window_offset.checked_sub(ZIP64_LOCATOR_BYTES) else {
        return Ok(None);
    };
    let Some(locator) = parse_zip64_locator(&trailer.bytes, locator_window_offset) else {
        return Ok(None);
    };
    if locator.total_disks > SINGLE_DISK || locator.disk_with_central_directory != FIRST_DISK {
        return Err(multi_disk_error());
    }
    let Some(locator_offset) = trailer.absolute(locator_window_offset) else {
        return Err(unaddressable_trailing_metadata());
    };
    let record_span = locator_offset
        .checked_sub(locator.footer_offset)
        .filter(|span| *span > 0);
    let Some(record_span) = record_span else {
        return Err(ReviewError::Archive(
            "archive ZIP64 end of central directory record is not before its locator".to_string(),
        ));
    };
    if record_span < ZIP64_FOOTER_BYTES {
        return Err(ReviewError::Archive(format!(
            "archive ZIP64 end of central directory record is shorter than {ZIP64_FOOTER_BYTES} bytes"
        )));
    }
    let window = read_fixed_window(
        file,
        locator.footer_offset,
        ZIP64_FOOTER_BYTES,
        "read archive ZIP64 end of central directory record",
    )?;
    let Some(footer) = parse_zip64_footer(&window, locator.footer_offset) else {
        return Err(ReviewError::Archive(
            "archive ZIP64 end of central directory record is malformed".to_string(),
        ));
    };
    if footer.record_bytes.checked_add(ZIP64_FOOTER_PREFIX_BYTES) != Some(record_span) {
        return Err(ReviewError::Archive(
            "archive ZIP64 end of central directory record length disagrees with its locator"
                .to_string(),
        ));
    }
    if footer.disk_number != FIRST_DISK || footer.disk_with_central_directory != FIRST_DISK {
        return Err(multi_disk_error());
    }
    if footer.entries_on_disk != footer.total_entries {
        return Err(inconsistent_entry_counts_error());
    }
    Ok(Some(footer))
}

fn parse_zip64_locator(window: &[u8], window_offset: usize) -> Option<Zip64Locator> {
    let bytes = window.get(window_offset..)?;
    if !bytes.starts_with(&ZIP64_LOCATOR_SIGNATURE) {
        return None;
    }
    let mut fields = FieldReader::new(bytes);
    fields.skip(SIGNATURE_BYTES)?;
    Some(Zip64Locator {
        disk_with_central_directory: fields.u32()?,
        footer_offset: fields.u64()?,
        total_disks: fields.u32()?,
    })
}

fn parse_zip64_footer(window: &[u8], offset: u64) -> Option<Zip64Footer> {
    if !window.starts_with(&ZIP64_FOOTER_SIGNATURE) {
        return None;
    }
    let mut fields = FieldReader::new(window);
    fields.skip(SIGNATURE_BYTES)?;
    let record_bytes = fields.u64()?;
    fields.skip(ZIP64_FOOTER_VERSION_BYTES)?;
    Some(Zip64Footer {
        offset,
        record_bytes,
        disk_number: fields.u32()?,
        disk_with_central_directory: fields.u32()?,
        entries_on_disk: fields.u64()?,
        total_entries: fields.u64()?,
        central_directory_size: fields.u64()?,
        central_directory_offset: fields.u64()?,
    })
}

fn declared_central_directory(
    trailer: &TrailingMetadata,
    classic: &ClassicFooter,
    zip64: Option<Zip64Footer>,
) -> Result<DeclaredCentralDirectory, ReviewError> {
    let Some(footer_offset) = trailer.absolute(classic.window_offset) else {
        return Err(unaddressable_trailing_metadata());
    };
    if let Some(zip64) = zip64 {
        return Ok(DeclaredCentralDirectory {
            entries: zip64.total_entries,
            size: zip64.central_directory_size,
            offset: zip64.central_directory_offset,
            footer_offset: zip64.offset,
        });
    }
    if u32::from(classic.disk_number) != FIRST_DISK
        || u32::from(classic.disk_with_central_directory) != FIRST_DISK
    {
        return Err(multi_disk_error());
    }
    if classic.entries_on_disk != classic.total_entries {
        return Err(inconsistent_entry_counts_error());
    }
    Ok(DeclaredCentralDirectory {
        entries: u64::from(classic.entries_on_disk),
        size: u64::from(classic.central_directory_size),
        offset: u64::from(classic.central_directory_offset),
        footer_offset,
    })
}

fn enforce_declared_entry_limit(
    declared_entries: u64,
    max_entries: usize,
) -> Result<(), ReviewError> {
    let limit = u64::try_from(max_entries).unwrap_or(u64::MAX);
    if declared_entries > limit {
        return Err(ReviewError::Archive(format!(
            "archive declares more than {max_entries} entries"
        )));
    }
    Ok(())
}

fn validate_central_directory_bounds(
    declared: &DeclaredCentralDirectory,
) -> Result<(), ReviewError> {
    let central_directory_end = declared.offset.checked_add(declared.size);
    if central_directory_end.is_none_or(|end| end > declared.footer_offset) {
        return Err(ReviewError::Archive(
            "archive central directory does not fit before its end of central directory record"
                .to_string(),
        ));
    }
    let required_bytes = declared.entries.checked_mul(MIN_CENTRAL_RECORD_BYTES);
    if required_bytes.is_none_or(|required| required > declared.size) {
        return Err(ReviewError::Archive(format!(
            "archive declares {} entries that do not fit in its {} byte central directory",
            declared.entries, declared.size
        )));
    }
    Ok(())
}

fn missing_classic_footer() -> ReviewError {
    ReviewError::Archive(format!(
        "archive has no end of central directory record in its last {MAX_TRAILING_METADATA_BYTES} bytes"
    ))
}

fn ambiguous_classic_footer() -> ReviewError {
    ReviewError::Archive(format!(
        "archive has more than one end of central directory record in its last {MAX_TRAILING_METADATA_BYTES} bytes"
    ))
}

fn unaddressable_trailing_metadata() -> ReviewError {
    ReviewError::Archive("archive trailing metadata is not addressable".to_string())
}

fn multi_disk_error() -> ReviewError {
    ReviewError::Archive("archive spans multiple disks".to_string())
}

fn inconsistent_entry_counts_error() -> ReviewError {
    ReviewError::Archive("archive declares inconsistent entry counts across disks".to_string())
}

fn inspect_archive(
    archive: &mut zip::ZipArchive<std::fs::File>,
    limits: ArchiveLimits,
) -> Result<(OsString, Vec<ArchiveEntry>), ReviewError> {
    if archive.len() > limits.max_entries {
        return Err(ReviewError::Archive(format!(
            "archive contains more than {} entries",
            limits.max_entries
        )));
    }

    let mut root_name = None;
    let mut output_paths = BTreeSet::new();
    let mut entries = Vec::with_capacity(archive.len());
    let mut extracted_bytes = 0u64;
    let mut retained_paths = RetainedPaths::new(limits.max_retained_path_bytes);

    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(archive_error)?;
        let enclosed_name = validated_entry_path(&entry, limits)?;
        let (entry_root, output_path) = split_archive_root(&enclosed_name)?;
        match &root_name {
            Some(expected) if expected != &entry_root => {
                return Err(ReviewError::Archive(
                    "archive contains multiple top-level roots".to_string(),
                ));
            }
            None => {
                retained_paths.retain(entry_root.as_os_str().len())?;
                root_name = Some(entry_root);
            }
            Some(_) => {}
        }

        validate_entry_type(&entry)?;
        validate_entry_size(&entry, &mut extracted_bytes, limits)?;
        if output_path.as_os_str().is_empty() {
            if !entry.is_dir() {
                return Err(ReviewError::Archive(format!(
                    "archive root entry is not a directory: {}",
                    reported_name(entry.name())
                )));
            }
            continue;
        }
        retained_paths.retain_copies(output_path.as_os_str().len(), 2)?;
        if !output_paths.insert(output_path.clone()) {
            return Err(ReviewError::Archive(format!(
                "archive contains duplicate path {}",
                reported_path(&output_path)
            )));
        }
        entries.push(ArchiveEntry {
            index,
            output_path,
            is_directory: entry.is_dir(),
            size: entry.size(),
        });
    }

    let root_name = require_archive_root(root_name)?;
    if entries.is_empty() {
        return Err(ReviewError::Archive(
            "archive contains no extractable files".to_string(),
        ));
    }
    Ok((root_name, entries))
}

fn validated_entry_path(
    entry: &zip::read::ZipFile<'_, std::fs::File>,
    limits: ArchiveLimits,
) -> Result<PathBuf, ReviewError> {
    let name = entry.name();
    if name.len() > limits.max_entry_name_bytes {
        return Err(ReviewError::Archive(format!(
            "archive path exceeds {} bytes: {}",
            limits.max_entry_name_bytes,
            reported_name(name)
        )));
    }
    if unsafe_archive_name(name) {
        return Err(ReviewError::Archive(format!(
            "unsafe archive path {}",
            reported_name(name)
        )));
    }
    let path = require_enclosed_path(entry.enclosed_name(), name)?;
    if path.components().count() > limits.max_path_depth {
        return Err(ReviewError::Archive(format!(
            "archive path exceeds {} components",
            limits.max_path_depth
        )));
    }
    Ok(path)
}
fn archive_error(error: zip::result::ZipError) -> ReviewError {
    ReviewError::Archive(error.to_string())
}

fn require_archive_root(root_name: Option<OsString>) -> Result<OsString, ReviewError> {
    match root_name {
        Some(root_name) => Ok(root_name),
        None => Err(ReviewError::Archive(
            "archive contains no entries".to_string(),
        )),
    }
}

fn reported_name(name: &str) -> String {
    let prefix = safe_truncate(name, REPORTED_NAME_BYTES);
    if prefix.len() == name.len() {
        return name.to_string();
    }
    format!("{prefix}… ({} bytes)", name.len())
}

fn reported_path(path: &Path) -> String {
    reported_name(&path.to_string_lossy())
}

fn require_enclosed_path(path: Option<PathBuf>, name: &str) -> Result<PathBuf, ReviewError> {
    match path {
        Some(path) => Ok(path),
        None => Err(ReviewError::Archive(format!(
            "unsafe archive path {}",
            reported_name(name)
        ))),
    }
}

fn unsafe_archive_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    name.starts_with('/')
        || name.contains('\\')
        || bytes
            .first()
            .zip(bytes.get(1))
            .is_some_and(|(first, second)| first.is_ascii_alphabetic() && *second == b':')
        || name
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn split_archive_root(path: &Path) -> Result<(OsString, PathBuf), ReviewError> {
    let mut components = path.components();
    let root = match components.next() {
        Some(Component::Normal(root)) => root.to_os_string(),
        _ => {
            return Err(ReviewError::Archive(format!(
                "unsafe archive path {}",
                reported_path(path)
            )));
        }
    };
    let output_path = components.collect();
    Ok((root, output_path))
}

fn validate_entry_type(entry: &zip::read::ZipFile<'_, std::fs::File>) -> Result<(), ReviewError> {
    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let file_type = mode & FILE_TYPE_MASK;
    if file_type == SYMBOLIC_LINK_MODE {
        return Err(ReviewError::Archive(format!(
            "symbolic link is not allowed: {}",
            reported_name(entry.name())
        )));
    }
    if file_type != 0 && file_type != REGULAR_FILE_MODE && file_type != DIRECTORY_MODE {
        return Err(ReviewError::Archive(format!(
            "special file is not allowed: {}",
            reported_name(entry.name())
        )));
    }
    Ok(())
}

fn validate_entry_size(
    entry: &zip::read::ZipFile<'_, std::fs::File>,
    extracted_bytes: &mut u64,
    limits: ArchiveLimits,
) -> Result<(), ReviewError> {
    if entry.size() > limits.max_entry_bytes {
        return Err(ReviewError::Archive(format!(
            "{} exceeds the per-entry size limit",
            reported_name(entry.name())
        )));
    }
    *extracted_bytes = extracted_bytes
        .checked_add(entry.size())
        .filter(|total| *total <= limits.max_extracted_bytes)
        .ok_or_else(|| {
            ReviewError::Archive(format!(
                "archive exceeds the {} byte extracted size limit",
                limits.max_extracted_bytes
            ))
        })?;
    let compressed_size = entry.compressed_size();
    if entry.size() > 1024 * 1024
        && (compressed_size == 0
            || entry.size() / compressed_size.max(1) > limits.max_compression_ratio)
    {
        return Err(ReviewError::Archive(format!(
            "{} exceeds the compression ratio limit",
            reported_name(entry.name())
        )));
    }
    Ok(())
}

fn extraction_read_limit(size: u64) -> Result<u64, ReviewError> {
    size.checked_add(1)
        .ok_or_else(|| ReviewError::Archive("archive entry size cannot be bounded".to_string()))
}

fn extract_entries(
    archive: &mut zip::ZipArchive<std::fs::File>,
    destination: &Path,
    entries: &[ArchiveEntry],
) -> Result<(), ReviewError> {
    for planned in entries {
        let output_path = destination.join(&planned.output_path);
        if planned.is_directory {
            std::fs::create_dir_all(&output_path).map_err(|source| ReviewError::Io {
                action: format!("create archive directory {}", output_path.display()),
                source,
            })?;
            continue;
        }
        let parent = output_path.parent().unwrap_or(destination);
        std::fs::create_dir_all(parent).map_err(|source| ReviewError::Io {
            action: format!("create archive directory {}", parent.display()),
            source,
        })?;
        let mut source = archive.by_index(planned.index).map_err(archive_error)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .map_err(|source| ReviewError::Io {
                action: format!("create archive file {}", output_path.display()),
                source,
            })?;
        let read_limit = extraction_read_limit(planned.size)?;
        let copied = std::io::copy(&mut source.by_ref().take(read_limit), &mut output).map_err(
            |source| ReviewError::Io {
                action: format!("extract archive file {}", output_path.display()),
                source,
            },
        )?;
        if copied != planned.size {
            return Err(ReviewError::Archive(format!(
                "archive entry size changed while extracting {}",
                output_path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn archive_with(entries: &[(&str, &[u8], Option<u32>)]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let mut archive = zip::ZipWriter::new(file.reopen().unwrap());
            for (name, content, mode) in entries {
                if mode.is_some_and(|mode| mode & FILE_TYPE_MASK == SYMBOLIC_LINK_MODE) {
                    archive
                        .add_symlink(
                            *name,
                            String::from_utf8_lossy(content),
                            SimpleFileOptions::default(),
                        )
                        .unwrap();
                    continue;
                }
                let options = mode.map_or_else(SimpleFileOptions::default, |mode| {
                    SimpleFileOptions::default().unix_permissions(mode)
                });
                archive.start_file(*name, options).unwrap();
                archive.write_all(content).unwrap();
            }
            archive.finish().unwrap();
        }
        file
    }

    #[test]
    fn extracts_regular_files_under_the_archive_root() {
        let archive = archive_with(&[("owner-project-sha/src/main.rs", b"fn main() {}\n", None)]);
        let destination = tempfile::tempdir().unwrap();

        let root =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
    }

    #[test]
    fn rejects_archive_paths_that_escape_the_destination() {
        let archive = archive_with(&[("../escape", b"owned", None)]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(error.to_string().contains("unsafe archive path"));
        assert!(!destination.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn rejects_symbolic_links() {
        let archive = archive_with(&[("owner-project-sha/link", b"target", Some(0o120777))]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(error.to_string().contains("symbolic link"));
    }

    #[test]
    fn rejects_malicious_root_only_entries() {
        let destination = tempfile::tempdir().unwrap();
        let symbolic_root = archive_with(&[
            ("root/", b"target", Some(0o120777)),
            ("root/file", b"x", None),
        ]);
        let symbolic_error = extract_zip_archive(
            symbolic_root.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(symbolic_error.to_string().contains("symbolic link"));

        let regular_root = archive_with(&[("root", b"payload", None), ("root/file", b"x", None)]);
        let regular_error = extract_zip_archive(
            regular_root.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(
            regular_error
                .to_string()
                .contains("root entry is not a directory")
        );
    }

    #[test]
    fn rejects_archives_beyond_the_extracted_size_limit() {
        let archive = archive_with(&[("owner-project-sha/file", b"12345", None)]);
        let destination = tempfile::tempdir().unwrap();
        let limits = ArchiveLimits {
            max_extracted_bytes: 4,
            ..ArchiveLimits::default()
        };

        let error = extract_zip_archive(archive.path(), destination.path(), limits).unwrap_err();

        assert!(error.to_string().contains("extracted size"));
    }

    #[test]
    fn rejects_archives_beyond_the_entry_limit() {
        let archive = archive_with(&[
            ("owner-project-sha/one", b"1", None),
            ("owner-project-sha/two", b"2", None),
        ]);
        let destination = tempfile::tempdir().unwrap();
        let limits = ArchiveLimits {
            max_entries: 1,
            ..ArchiveLimits::default()
        };

        let error = extract_zip_archive(archive.path(), destination.path(), limits).unwrap_err();

        assert!(error.to_string().contains("more than 1 entries"));
    }

    #[test]
    fn rejects_missing_and_oversized_archive_files() {
        let destination = tempfile::tempdir().unwrap();
        let missing = destination.path().join("missing.zip");
        let error = extract_zip_archive(&missing, destination.path(), ArchiveLimits::default())
            .unwrap_err();
        assert!(error.to_string().contains("inspect pull request archive"));

        let archive = archive_with(&[("root/file", b"x", None)]);
        let limits = ArchiveLimits {
            max_archive_bytes: std::fs::metadata(archive.path()).unwrap().len() - 1,
            ..ArchiveLimits::default()
        };
        let error = extract_zip_archive(archive.path(), destination.path(), limits).unwrap_err();
        assert!(error.to_string().contains("downloaded archive exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn reports_an_archive_that_cannot_be_opened() {
        use std::os::unix::fs::PermissionsExt;

        let archive = archive_with(&[("root/file", b"x", None)]);
        std::fs::set_permissions(archive.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(error.to_string().contains("open pull request archive"));
    }

    #[test]
    fn rejects_empty_roots_multiple_roots_and_duplicate_paths() {
        let destination = tempfile::tempdir().unwrap();

        let root_only = archive_with(&[("root/", b"", None)]);
        let error = extract_zip_archive(
            root_only.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no extractable files"));

        let multiple = archive_with(&[("one/a", b"a", None), ("two/b", b"b", None)]);
        let error = extract_zip_archive(
            multiple.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("multiple top-level roots"));

        let duplicate = archive_with(&[("root/a", b"a", None), ("root/a/", b"b", None)]);
        let error = extract_zip_archive(
            duplicate.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate path"));
    }

    #[test]
    fn rejects_backslash_paths_and_paths_beyond_the_depth_limit() {
        let destination = tempfile::tempdir().unwrap();

        let backslash = archive_with(&[("root\\file", b"x", None)]);
        let error = extract_zip_archive(
            backslash.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unsafe archive path"));

        let deep = archive_with(&[("root/a/b", b"x", None)]);
        let limits = ArchiveLimits {
            max_path_depth: 2,
            ..ArchiveLimits::default()
        };
        let error = extract_zip_archive(deep.path(), destination.path(), limits).unwrap_err();
        assert!(error.to_string().contains("exceeds 2 components"));
    }

    #[test]
    fn rejects_entries_beyond_size_and_compression_limits() {
        let destination = tempfile::tempdir().unwrap();
        let oversized = archive_with(&[("root/file", b"12345", None)]);
        let limits = ArchiveLimits {
            max_entry_bytes: 4,
            ..ArchiveLimits::default()
        };
        let error = extract_zip_archive(oversized.path(), destination.path(), limits).unwrap_err();
        assert!(error.to_string().contains("per-entry size limit"));

        let compressed = tempfile::NamedTempFile::new().unwrap();
        {
            let mut writer = zip::ZipWriter::new(compressed.reopen().unwrap());
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("root/bomb", options).unwrap();
            writer.write_all(&vec![0; 2 * 1024 * 1024]).unwrap();
            writer.finish().unwrap();
        }
        let limits = ArchiveLimits {
            max_compression_ratio: 2,
            ..ArchiveLimits::default()
        };
        let error = extract_zip_archive(compressed.path(), destination.path(), limits).unwrap_err();
        assert!(error.to_string().contains("compression ratio limit"));
    }

    #[test]
    fn extracts_directory_entries_and_refuses_existing_destinations() {
        let archive = archive_with(&[
            ("root/sub/", b"", Some(DIRECTORY_MODE | 0o755)),
            ("root/sub/file", b"x", None),
        ]);
        let destination = tempfile::tempdir().unwrap();
        let root =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap();
        assert!(root.join("sub").is_dir());
        assert_eq!(std::fs::read(root.join("sub/file")).unwrap(), b"x");

        let archive = archive_with(&[("root/file", b"x", None)]);
        let destination = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(destination.path().join("root")).unwrap();
        std::fs::write(destination.path().join("root/file"), "existing").unwrap();
        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();
        assert!(error.to_string().contains("create archive file"));
    }

    #[test]
    fn reports_destination_root_creation_failures() {
        let archive = archive_with(&[("root/file", b"x", None)]);
        let destination = tempfile::tempdir().unwrap();
        std::fs::write(destination.path().join("root"), "not a directory").unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("create pull request archive root")
        );
    }

    struct RawEntry<'a> {
        name: &'a str,
        data: &'a [u8],
        method: u16,
        external_attributes: u32,
        declared_size: Option<u32>,
    }

    impl<'a> RawEntry<'a> {
        fn stored(name: &'a str, data: &'a [u8]) -> Self {
            Self {
                name,
                data,
                method: 0,
                external_attributes: 0o100644 << 16,
                declared_size: None,
            }
        }

        fn with_external_attributes(mut self, external_attributes: u32) -> Self {
            self.external_attributes = external_attributes;
            self
        }

        fn with_method(mut self, method: u16) -> Self {
            self.method = method;
            self
        }

        fn with_declared_size(mut self, declared_size: u32) -> Self {
            self.declared_size = Some(declared_size);
            self
        }
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut checksum = 0xFFFF_FFFFu32;
        for byte in bytes {
            checksum ^= u32::from(*byte);
            for _ in 0..8 {
                checksum = if checksum & 1 == 0 {
                    checksum >> 1
                } else {
                    (checksum >> 1) ^ 0xEDB8_8320
                };
            }
        }
        !checksum
    }

    struct RawArchive {
        bytes: Vec<u8>,
        central_offset: u32,
        central_size: u32,
        entries: u16,
    }

    struct ClassicFooterFixture {
        disk_number: u16,
        disk_with_central_directory: u16,
        entries_on_disk: u16,
        total_entries: u16,
        central_size: u32,
        central_offset: u32,
        comment_bytes: u16,
    }

    impl ClassicFooterFixture {
        fn new(body: &RawArchive) -> Self {
            Self {
                disk_number: 0,
                disk_with_central_directory: 0,
                entries_on_disk: body.entries,
                total_entries: body.entries,
                central_size: body.central_size,
                central_offset: body.central_offset,
                comment_bytes: 0,
            }
        }

        fn with_zip64_sentinels(body: &RawArchive, total_entries: u16) -> Self {
            Self {
                total_entries,
                central_size: u32::MAX,
                central_offset: u32::MAX,
                ..Self::new(body)
            }
        }

        fn with_declared_entries(mut self, entries: u16) -> Self {
            self.entries_on_disk = entries;
            self.total_entries = entries;
            self
        }

        fn with_total_entries(mut self, total_entries: u16) -> Self {
            self.total_entries = total_entries;
            self
        }

        fn with_disk_number(mut self, disk_number: u16) -> Self {
            self.disk_number = disk_number;
            self
        }

        fn with_central_offset(mut self, central_offset: u32) -> Self {
            self.central_offset = central_offset;
            self
        }

        fn with_comment_bytes(mut self, comment_bytes: u16) -> Self {
            self.comment_bytes = comment_bytes;
            self
        }

        fn bytes(&self) -> Vec<u8> {
            let mut footer = Vec::new();
            footer.extend_from_slice(&CLASSIC_FOOTER_SIGNATURE);
            footer.extend_from_slice(&self.disk_number.to_le_bytes());
            footer.extend_from_slice(&self.disk_with_central_directory.to_le_bytes());
            footer.extend_from_slice(&self.entries_on_disk.to_le_bytes());
            footer.extend_from_slice(&self.total_entries.to_le_bytes());
            footer.extend_from_slice(&self.central_size.to_le_bytes());
            footer.extend_from_slice(&self.central_offset.to_le_bytes());
            footer.extend_from_slice(&self.comment_bytes.to_le_bytes());
            footer
        }
    }

    fn archive_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        file
    }

    fn sealed_archive(body: &RawArchive, trailer: &[u8]) -> tempfile::NamedTempFile {
        archive_file(&[body.bytes.as_slice(), trailer].concat())
    }

    fn raw_archive(entries: &[RawEntry<'_>]) -> tempfile::NamedTempFile {
        let body = raw_archive_body(entries);
        sealed_archive(&body, &ClassicFooterFixture::new(&body).bytes())
    }

    fn raw_archive_body(entries: &[RawEntry<'_>]) -> RawArchive {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for entry in entries {
            let checksum = crc32(entry.data);
            let compressed_size = entry.data.len() as u32;
            let uncompressed_size = entry.declared_size.unwrap_or(compressed_size);
            let name_length = entry.name.len() as u16;
            let header_offset = bytes.len() as u32;

            bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&entry.method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0x21u16.to_le_bytes());
            bytes.extend_from_slice(&checksum.to_le_bytes());
            bytes.extend_from_slice(&compressed_size.to_le_bytes());
            bytes.extend_from_slice(&uncompressed_size.to_le_bytes());
            bytes.extend_from_slice(&name_length.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(entry.name.as_bytes());
            bytes.extend_from_slice(entry.data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&((3u16 << 8) | 30).to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&entry.method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0x21u16.to_le_bytes());
            central.extend_from_slice(&checksum.to_le_bytes());
            central.extend_from_slice(&compressed_size.to_le_bytes());
            central.extend_from_slice(&uncompressed_size.to_le_bytes());
            central.extend_from_slice(&name_length.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&entry.external_attributes.to_le_bytes());
            central.extend_from_slice(&header_offset.to_le_bytes());
            central.extend_from_slice(entry.name.as_bytes());
        }

        let central_offset = bytes.len() as u32;
        let central_size = central.len() as u32;
        let count = entries.len() as u16;
        bytes.extend_from_slice(&central);

        RawArchive {
            bytes,
            central_offset,
            central_size,
            entries: count,
        }
    }

    #[test]
    fn accepts_entries_whose_mode_carries_no_file_type() {
        let archive = raw_archive(&[
            RawEntry::stored("root/plain", b"plain\n").with_external_attributes(0),
            RawEntry::stored("root/readonly", b"readonly\n").with_external_attributes(0x01),
        ]);
        let destination = tempfile::tempdir().unwrap();

        let root =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("plain")).unwrap(),
            "plain\n",
            "an entry without unix metadata is a plain file, not a rejected special file"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("readonly")).unwrap(),
            "readonly\n"
        );
    }

    #[test]
    fn rejects_special_files() {
        let archive = raw_archive(&[
            RawEntry::stored("root/fifo", b"").with_external_attributes(0o010644 << 16)
        ]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert_eq!(
            error.to_string(),
            "pull request archive failed validation: special file is not allowed: root/fifo"
        );
        assert!(!destination.path().join("root/fifo").exists());
    }

    #[test]
    fn rejects_entries_without_a_named_root() {
        let archive = archive_with(&[("root/..", b"x", None)]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(
            error.to_string().contains("unsafe archive path"),
            "an entry that resolves above its own root has no usable root name: {error}"
        );
    }

    #[test]
    fn reports_entries_that_cannot_be_decompressed() {
        let archive = raw_archive(&[RawEntry::stored("root/bad", &[0xFF; 8])
            .with_method(8)
            .with_declared_size(64)]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert!(
            error.to_string().starts_with("extract archive file "),
            "{error}"
        );
    }

    #[test]
    fn rejects_entries_whose_declared_size_is_not_delivered() {
        let archive =
            raw_archive(&[RawEntry::stored("root/short", b"12345").with_declared_size(10)]);
        let destination = tempfile::tempdir().unwrap();

        let error =
            extract_zip_archive(archive.path(), destination.path(), ArchiveLimits::default())
                .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "pull request archive failed validation: \
             archive entry size changed while extracting {}",
                destination.path().join("root").join("short").display()
            )
        );
    }

    #[test]
    fn reports_archive_directories_that_collide_with_extracted_files() {
        let file_parent = archive_with(&[("root/a", b"a", None), ("root/a/b", b"b", None)]);
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_archive(
            file_parent.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();

        assert!(
            error.to_string().starts_with("create archive directory "),
            "{error}"
        );
        assert!(!destination.path().join("root/a/b").exists());

        let directory_entry = archive_with(&[("root/x", b"x", None), ("root/x/y/", b"", None)]);
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_archive(
            directory_entry.path(),
            destination.path(),
            ArchiveLimits::default(),
        )
        .unwrap_err();

        assert!(
            error.to_string().starts_with("create archive directory "),
            "{error}"
        );
    }

    fn contained_tree(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for child in std::fs::read_dir(&directory).expect("directory is readable") {
                let path = child.expect("directory entry").path();
                let relative = path
                    .strip_prefix(root)
                    .expect("entry escaped the walked root")
                    .to_path_buf();
                for component in relative.components() {
                    assert!(
                        matches!(component, Component::Normal(_)),
                        "{} is not a normalized relative path",
                        relative.display()
                    );
                }
                assert!(
                    !std::fs::symlink_metadata(&path)
                        .expect("entry metadata")
                        .file_type()
                        .is_symlink(),
                    "{} is a symbolic link",
                    relative.display()
                );
                if path.is_dir() {
                    pending.push(path);
                }
                found.push(relative);
            }
        }
        found.sort();
        found
    }

    fn raw_seed_archives() -> Vec<(String, Vec<u8>)> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/archive_extraction");
        let mut seeds = Vec::new();
        for entry in std::fs::read_dir(&directory).expect("committed archive seed corpus") {
            let path = entry.expect("seed directory entry").path();
            let name = path
                .file_name()
                .expect("seed file name")
                .to_string_lossy()
                .into_owned();
            if !name.starts_with("raw-") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("seed contents");
            let (_, archive) = bytes.split_first().expect("seed selector byte");
            seeds.push((name, archive.to_vec()));
        }
        seeds.sort();
        seeds
    }

    #[test]
    fn archive_extraction_seed_corpus_raw_archives_are_rejected_or_contained() {
        let seeds = raw_seed_archives();
        for required in [
            "raw-block-device-external-attr",
            "raw-central-size-mismatch",
            "raw-character-device-external-attr",
            "raw-empty",
            "raw-fifo-external-attr",
            "raw-no-unix-mode",
            "raw-not-a-zip",
            "raw-socket-external-attr",
            "raw-symlink-external-attr",
            "raw-truncated-archive",
        ] {
            assert!(
                seeds.iter().any(|(name, _)| name == required),
                "the committed archive_extraction corpus lost the {required} seed"
            );
        }

        for (name, bytes) in &seeds {
            let sandbox = tempfile::tempdir().unwrap();
            let destination = sandbox.path().join("dest");
            std::fs::create_dir(&destination).unwrap();
            let archive_path = sandbox.path().join("input.zip");
            std::fs::write(&archive_path, bytes).unwrap();

            match extract_zip_archive(&archive_path, &destination, ArchiveLimits::default()) {
                Ok(root) => assert!(
                    root.strip_prefix(&destination)
                        .expect("root escaped the destination")
                        .components()
                        .count()
                        == 1,
                    "{name} produced the multi-component root {}",
                    root.display()
                ),
                Err(error) => assert!(
                    matches!(error, ReviewError::Archive(_) | ReviewError::Io { .. }),
                    "{name} produced the untyped error {error:?}"
                ),
            }

            contained_tree(&destination);
            assert_eq!(
                contained_tree(sandbox.path())
                    .into_iter()
                    .filter(|path| !path.starts_with("dest"))
                    .collect::<Vec<_>>(),
                vec![PathBuf::from("input.zip")],
                "{name} created files outside the destination"
            );
        }
    }

    #[test]
    fn archive_extraction_seed_unsafe_paths_never_escape_the_destination() {
        for entry_name in [
            "../escape",
            "owner-project-sha/../../escape",
            "owner-project-sha/src/../main.rs",
            "owner-project-sha/./src/main.rs",
            "/etc/passwd",
            "C:/Windows/System32/config",
            "owner-project-sha\\src\\main.rs",
        ] {
            let archive = archive_with(&[(entry_name, b"owned", None)]);
            let sandbox = tempfile::tempdir().unwrap();
            let destination = sandbox.path().join("dest");
            std::fs::create_dir(&destination).unwrap();

            let error = extract_zip_archive(archive.path(), &destination, ArchiveLimits::default())
                .unwrap_err();

            assert!(
                matches!(error, ReviewError::Archive(_)),
                "{entry_name} produced {error:?}"
            );
            assert_eq!(
                contained_tree(sandbox.path()),
                vec![PathBuf::from("dest")],
                "{entry_name} created files outside the destination"
            );
        }
    }

    #[test]
    fn archive_extraction_seed_accepted_paths_are_normalized_and_deterministic() {
        let entries: &[(&str, &[u8], Option<u32>)] = &[
            ("owner-project-sha/README", b"hi\n", None),
            (
                "owner-project-sha/src/deep/mod.rs",
                b"pub fn f() {}\n",
                None,
            ),
            (
                "owner-project-sha/src/main.rs",
                b"fn main() {}\n",
                Some(0o100644),
            ),
        ];
        let archive = archive_with(entries);
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();

        let first_root =
            extract_zip_archive(archive.path(), first.path(), ArchiveLimits::default()).unwrap();
        let second_root =
            extract_zip_archive(archive.path(), second.path(), ArchiveLimits::default()).unwrap();

        let relative_root = first_root.strip_prefix(first.path()).unwrap();
        assert_eq!(
            relative_root,
            second_root.strip_prefix(second.path()).unwrap()
        );
        assert_eq!(relative_root, Path::new("owner-project-sha"));
        assert_eq!(
            contained_tree(first.path()),
            contained_tree(second.path()),
            "extraction is not deterministic across destinations"
        );
        assert_eq!(
            contained_tree(first.path()),
            vec![
                PathBuf::from("owner-project-sha"),
                PathBuf::from("owner-project-sha/README"),
                PathBuf::from("owner-project-sha/src"),
                PathBuf::from("owner-project-sha/src/deep"),
                PathBuf::from("owner-project-sha/src/deep/mod.rs"),
                PathBuf::from("owner-project-sha/src/main.rs"),
            ]
        );
        assert_eq!(
            std::fs::read_to_string(first_root.join("src/deep/mod.rs")).unwrap(),
            "pub fn f() {}\n"
        );
    }
    #[test]
    fn archive_error_helpers_reject_invalid_internal_states() {
        let archive_error = archive_error(zip::result::ZipError::FileNotFound);
        assert!(
            archive_error
                .to_string()
                .contains("specified file not found")
        );

        let root_error = require_archive_root(None).unwrap_err();
        assert!(root_error.to_string().contains("no entries"));

        let path_error = require_enclosed_path(None, "unsafe").unwrap_err();
        assert!(path_error.to_string().contains("unsafe archive path"));

        let split_error = split_archive_root(Path::new("/")).unwrap_err();
        assert!(split_error.to_string().contains("unsafe archive path"));
    }

    const ZIP64_MINIMUM_RECORD_BYTES: u64 = ZIP64_FOOTER_BYTES - ZIP64_FOOTER_PREFIX_BYTES;
    const ZIP64_VERSION: u16 = 45;

    struct Zip64Fixture {
        declared_entries: u64,
        entries_on_disk: Option<u64>,
        footer_disk: u32,
        footer_signature: [u8; SIGNATURE_BYTES],
        record_bytes: Option<u64>,
        footer_shift: u64,
        locator_disk_with_central_directory: u32,
        locator_total_disks: u32,
        classic_total_entries: u16,
    }

    impl Zip64Fixture {
        fn declaring(declared_entries: u64) -> Self {
            Self {
                declared_entries,
                entries_on_disk: None,
                footer_disk: 0,
                footer_signature: ZIP64_FOOTER_SIGNATURE,
                record_bytes: None,
                footer_shift: 0,
                locator_disk_with_central_directory: 0,
                locator_total_disks: 1,
                classic_total_entries: u16::MAX,
            }
        }

        fn with_entries_on_disk(mut self, entries_on_disk: u64) -> Self {
            self.entries_on_disk = Some(entries_on_disk);
            self
        }

        fn with_footer_disk(mut self, footer_disk: u32) -> Self {
            self.footer_disk = footer_disk;
            self
        }

        fn with_corrupt_footer_signature(mut self) -> Self {
            self.footer_signature = [0; SIGNATURE_BYTES];
            self
        }

        fn with_record_bytes(mut self, record_bytes: u64) -> Self {
            self.record_bytes = Some(record_bytes);
            self
        }

        fn with_footer_shifted_forward(mut self, footer_shift: u64) -> Self {
            self.footer_shift = footer_shift;
            self
        }

        fn with_locator_disks(mut self, locator_total_disks: u32) -> Self {
            self.locator_total_disks = locator_total_disks;
            self
        }

        fn with_locator_disk_with_central_directory(mut self, disk: u32) -> Self {
            self.locator_disk_with_central_directory = disk;
            self
        }

        fn with_classic_total_entries(mut self, classic_total_entries: u16) -> Self {
            self.classic_total_entries = classic_total_entries;
            self
        }

        fn build(&self, entries: &[RawEntry<'_>]) -> tempfile::NamedTempFile {
            let body = raw_archive_body(entries);
            let footer_offset = u64::try_from(body.bytes.len()).unwrap();
            let record_bytes = self.record_bytes.unwrap_or(ZIP64_MINIMUM_RECORD_BYTES);
            let declared_offset = footer_offset + self.footer_shift;

            let mut trailer = Vec::new();
            trailer.extend_from_slice(&self.footer_signature);
            trailer.extend_from_slice(&record_bytes.to_le_bytes());
            trailer.extend_from_slice(&ZIP64_VERSION.to_le_bytes());
            trailer.extend_from_slice(&ZIP64_VERSION.to_le_bytes());
            trailer.extend_from_slice(&self.footer_disk.to_le_bytes());
            trailer.extend_from_slice(&self.footer_disk.to_le_bytes());
            trailer.extend_from_slice(
                &self
                    .entries_on_disk
                    .unwrap_or(self.declared_entries)
                    .to_le_bytes(),
            );
            trailer.extend_from_slice(&self.declared_entries.to_le_bytes());
            trailer.extend_from_slice(&u64::from(body.central_size).to_le_bytes());
            trailer.extend_from_slice(&u64::from(body.central_offset).to_le_bytes());
            trailer.extend_from_slice(&ZIP64_LOCATOR_SIGNATURE);
            trailer.extend_from_slice(&self.locator_disk_with_central_directory.to_le_bytes());
            trailer.extend_from_slice(&declared_offset.to_le_bytes());
            trailer.extend_from_slice(&self.locator_total_disks.to_le_bytes());
            trailer.extend_from_slice(
                &ClassicFooterFixture::with_zip64_sentinels(&body, self.classic_total_entries)
                    .bytes(),
            );

            sealed_archive(&body, &trailer)
        }
    }

    fn rejection(archive: &Path, limits: ArchiveLimits) -> String {
        let destination = tempfile::tempdir().unwrap();
        let error = extract_zip_archive(archive, destination.path(), limits).unwrap_err();
        assert_eq!(
            contained_tree(destination.path()),
            Vec::<PathBuf>::new(),
            "a rejected archive left files behind: {error}"
        );
        error.to_string()
    }

    fn archive_rejection(reason: &str) -> String {
        format!("pull request archive failed validation: {reason}")
    }

    #[test]
    fn classic_footers_that_overcount_entries_are_rejected_before_parsing() {
        let body = raw_archive_body(&[RawEntry::stored("root/one", b"1")]);
        let archive = sealed_archive(
            &body,
            &ClassicFooterFixture::new(&body)
                .with_declared_entries(64)
                .bytes(),
        );
        let limits = ArchiveLimits {
            max_entries: 8,
            ..ArchiveLimits::default()
        };

        assert_eq!(
            rejection(archive.path(), limits),
            archive_rejection("archive declares more than 8 entries")
        );
    }

    #[test]
    fn duplicate_central_records_cannot_hide_an_overcounted_declaration() {
        let archive = raw_archive(&[
            RawEntry::stored("root/same", b"1"),
            RawEntry::stored("root/same", b"2"),
        ]);
        let parsed = zip::ZipArchive::new(std::fs::File::open(archive.path()).unwrap()).unwrap();
        assert_eq!(
            parsed.len(),
            1,
            "the parser collapses duplicate central records, so only the declaration reveals the count"
        );
        let limits = ArchiveLimits {
            max_entries: 1,
            ..ArchiveLimits::default()
        };

        assert_eq!(
            rejection(archive.path(), limits),
            archive_rejection("archive declares more than 1 entries")
        );
    }

    #[test]
    fn zip64_footers_that_overcount_entries_are_rejected_before_parsing() {
        let archive =
            Zip64Fixture::declaring(10_000_000).build(&[RawEntry::stored("root/one", b"1")]);

        assert_eq!(
            rejection(archive.path(), ArchiveLimits::default()),
            archive_rejection("archive declares more than 100000 entries")
        );
    }

    #[test]
    fn valid_zip64_declarations_override_misleading_classic_entry_counts() {
        let entries = [RawEntry::stored("root/one", b"1")];
        let central_size = raw_archive_body(&entries).central_size;
        let limits = ArchiveLimits {
            max_entries: 4,
            ..ArchiveLimits::default()
        };

        let over_limit = Zip64Fixture::declaring(5)
            .with_classic_total_entries(1)
            .build(&entries);
        assert_eq!(
            rejection(over_limit.path(), limits),
            archive_rejection("archive declares more than 4 entries")
        );

        let at_limit = Zip64Fixture::declaring(4)
            .with_classic_total_entries(1)
            .build(&entries);
        assert_eq!(
            rejection(at_limit.path(), limits),
            archive_rejection(&format!(
                "archive declares 4 entries that do not fit in its {central_size} byte central directory"
            )),
            "the entry limit accepts exactly the limit and leaves the structural check to report"
        );
    }

    #[test]
    fn multi_disk_and_inconsistent_entry_declarations_are_rejected() {
        let entries = [RawEntry::stored("root/one", b"1")];
        let body = raw_archive_body(&entries);
        let limits = ArchiveLimits::default();
        let multi_disk = archive_rejection("archive spans multiple disks");
        let inconsistent =
            archive_rejection("archive declares inconsistent entry counts across disks");

        let classic_disk = sealed_archive(
            &body,
            &ClassicFooterFixture::new(&body).with_disk_number(1).bytes(),
        );
        assert_eq!(rejection(classic_disk.path(), limits), multi_disk);

        let classic_counts = sealed_archive(
            &body,
            &ClassicFooterFixture::new(&body)
                .with_total_entries(2)
                .bytes(),
        );
        assert_eq!(rejection(classic_counts.path(), limits), inconsistent);

        let locator_disks = Zip64Fixture::declaring(1)
            .with_locator_disks(2)
            .build(&entries);
        assert_eq!(rejection(locator_disks.path(), limits), multi_disk);

        let locator_disk_index = Zip64Fixture::declaring(1)
            .with_locator_disk_with_central_directory(1)
            .build(&entries);
        assert_eq!(rejection(locator_disk_index.path(), limits), multi_disk);

        let zip64_disk = Zip64Fixture::declaring(1)
            .with_footer_disk(1)
            .build(&entries);
        assert_eq!(rejection(zip64_disk.path(), limits), multi_disk);

        let zip64_counts = Zip64Fixture::declaring(1)
            .with_entries_on_disk(2)
            .build(&entries);
        assert_eq!(rejection(zip64_counts.path(), limits), inconsistent);
    }

    #[test]
    fn invalid_zip64_offsets_and_record_lengths_are_rejected() {
        let entries = [RawEntry::stored("root/one", b"1")];
        let limits = ArchiveLimits::default();

        let at_locator = Zip64Fixture::declaring(1)
            .with_footer_shifted_forward(ZIP64_FOOTER_BYTES)
            .build(&entries);
        assert_eq!(
            rejection(at_locator.path(), limits),
            archive_rejection(
                "archive ZIP64 end of central directory record is not before its locator"
            )
        );

        let truncated = Zip64Fixture::declaring(1)
            .with_footer_shifted_forward(ZIP64_FOOTER_BYTES - ZIP64_FOOTER_PREFIX_BYTES)
            .build(&entries);
        assert_eq!(
            rejection(truncated.path(), limits),
            archive_rejection(&format!(
                "archive ZIP64 end of central directory record is shorter than {ZIP64_FOOTER_BYTES} bytes"
            ))
        );

        let malformed = Zip64Fixture::declaring(1)
            .with_corrupt_footer_signature()
            .build(&entries);
        assert_eq!(
            rejection(malformed.path(), limits),
            archive_rejection("archive ZIP64 end of central directory record is malformed")
        );

        let mismatched = Zip64Fixture::declaring(1)
            .with_record_bytes(64)
            .build(&entries);
        assert_eq!(
            rejection(mismatched.path(), limits),
            archive_rejection(
                "archive ZIP64 end of central directory record length disagrees with its locator"
            )
        );
    }

    #[test]
    fn archives_without_a_terminating_footer_are_rejected() {
        let limits = ArchiveLimits::default();
        let expected = archive_rejection(&format!(
            "archive has no end of central directory record in its last {MAX_TRAILING_METADATA_BYTES} bytes"
        ));

        let empty = archive_file(b"");
        assert_eq!(rejection(empty.path(), limits), expected);

        let not_a_zip = archive_file(b"not a zip archive at all");
        assert_eq!(rejection(not_a_zip.path(), limits), expected);

        let body = raw_archive_body(&[RawEntry::stored("root/one", b"1")]);
        let lying_comment = sealed_archive(
            &body,
            &ClassicFooterFixture::new(&body)
                .with_comment_bytes(7)
                .bytes(),
        );
        assert_eq!(rejection(lying_comment.path(), limits), expected);
    }

    #[test]
    fn central_directories_that_overrun_their_footer_are_rejected() {
        let body = raw_archive_body(&[RawEntry::stored("root/one", b"1")]);
        let footer_offset = u32::try_from(body.bytes.len()).unwrap();
        let archive = sealed_archive(
            &body,
            &ClassicFooterFixture::new(&body)
                .with_central_offset(footer_offset)
                .bytes(),
        );

        assert_eq!(
            rejection(archive.path(), ArchiveLimits::default()),
            archive_rejection(
                "archive central directory does not fit before its end of central directory record"
            )
        );
    }

    #[test]
    fn archives_extract_at_the_exact_declared_entry_limit() {
        let archive = archive_with(&[
            ("root/one", b"1", None),
            ("root/two", b"2", None),
            ("root/three", b"3", None),
        ]);
        let destination = tempfile::tempdir().unwrap();
        let at_limit = ArchiveLimits {
            max_entries: 3,
            ..ArchiveLimits::default()
        };

        let root = extract_zip_archive(archive.path(), destination.path(), at_limit).unwrap();

        assert_eq!(std::fs::read(root.join("two")).unwrap(), b"2");
        let below_limit = ArchiveLimits {
            max_entries: 2,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            rejection(archive.path(), below_limit),
            archive_rejection("archive declares more than 2 entries")
        );
    }

    fn zip64_archive(
        extensible_sector: &[u8],
        entries: &[(&str, &[u8])],
    ) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        writer.set_raw_zip64_extensible_data_sector(extensible_sector.to_vec().into_boxed_slice());
        for (name, content) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
        file
    }

    #[test]
    fn zip64_archives_extract_within_the_declared_entry_limit() {
        let file = zip64_archive(&[], &[("root/one", b"one\n"), ("root/two", b"two\n")]);
        let destination = tempfile::tempdir().unwrap();
        let at_limit = ArchiveLimits {
            max_entries: 2,
            ..ArchiveLimits::default()
        };

        let root = extract_zip_archive(file.path(), destination.path(), at_limit).unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("one")).unwrap(),
            "one\n",
            "ZIP64 archives must still extract"
        );
        assert_eq!(std::fs::read_to_string(root.join("two")).unwrap(), "two\n");

        let below_limit = ArchiveLimits {
            max_entries: 1,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            rejection(file.path(), below_limit),
            archive_rejection("archive declares more than 1 entries")
        );
    }

    #[test]
    fn zip64_footers_longer_than_the_read_window_still_extract() {
        let file = zip64_archive(&[7; 64], &[("root/only", b"only\n")]);
        let destination = tempfile::tempdir().unwrap();

        let root =
            extract_zip_archive(file.path(), destination.path(), ArchiveLimits::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("only")).unwrap(),
            "only\n",
            "an extensible data sector must not be mistaken for an inconsistent record length"
        );
    }

    #[test]
    fn the_classic_entry_count_sentinel_is_accepted_without_a_zip64_locator() {
        let entries = u64::from(u16::MAX);
        let central_size = u32::try_from(entries * MIN_CENTRAL_RECORD_BYTES).unwrap();
        let body = RawArchive {
            bytes: vec![0; usize::try_from(central_size).unwrap()],
            central_offset: 0,
            central_size,
            entries: u16::MAX,
        };
        let archive = sealed_archive(&body, &ClassicFooterFixture::new(&body).bytes());
        let mut file = std::fs::File::open(archive.path()).unwrap();
        let archive_bytes = file.metadata().unwrap().len();

        preflight_declared_entries(&mut file, archive_bytes, ArchiveLimits::default()).unwrap();

        assert_eq!(
            file.stream_position().unwrap(),
            0,
            "the parser must receive the reader at the start of the archive"
        );
    }

    #[test]
    fn end_of_central_directory_records_hidden_in_the_comment_are_rejected() {
        let body = raw_archive_body(&[RawEntry::stored("root/one", b"1")]);
        let decoy = ClassicFooterFixture::new(&body)
            .with_declared_entries(u16::MAX - 1)
            .bytes();
        let comment_bytes = u16::try_from(decoy.len()).unwrap();
        let mut trailer = ClassicFooterFixture::new(&body)
            .with_comment_bytes(comment_bytes)
            .bytes();
        trailer.extend_from_slice(&decoy);
        let archive = sealed_archive(&body, &trailer);

        assert!(
            zip::ZipArchive::new(std::fs::File::open(archive.path()).unwrap()).is_ok(),
            "the fixture must be one the parser would happily open"
        );
        assert_eq!(
            rejection(archive.path(), ArchiveLimits::default()),
            archive_rejection(&format!(
                "archive has more than one end of central directory record in its last {MAX_TRAILING_METADATA_BYTES} bytes"
            ))
        );
    }

    #[test]
    fn entry_names_are_capped_at_the_name_limit() {
        let limits = ArchiveLimits::default();
        let exact = format!(
            "root/{}",
            "n".repeat(limits.max_entry_name_bytes - "root/".len())
        );
        assert_eq!(exact.len(), limits.max_entry_name_bytes);

        let accepted = archive_with(&[(exact.as_str(), b"x", None)]);
        let mut parsed =
            zip::ZipArchive::new(std::fs::File::open(accepted.path()).unwrap()).unwrap();
        let (root_name, entries) = inspect_archive(&mut parsed, limits).unwrap();
        assert_eq!(root_name, OsString::from("root"));
        assert_eq!(entries.len(), 1);

        let rejected = archive_with(&[(format!("{exact}n").as_str(), b"x", None)]);
        let message = rejection(rejected.path(), limits);
        assert!(
            message.starts_with(&archive_rejection(&format!(
                "archive path exceeds {} bytes: root/nnn",
                limits.max_entry_name_bytes
            ))),
            "{message}"
        );
    }

    #[test]
    fn untrusted_names_are_reported_as_bounded_prefixes() {
        let limits = ArchiveLimits::default();
        let bound = archive_rejection("").len() + REPORTED_NAME_BYTES + 64;

        let huge = format!("root/{}", "n".repeat(60_000));
        let archive = archive_with(&[(huge.as_str(), b"x", None)]);
        let message = rejection(archive.path(), limits);
        assert!(
            message.contains(&format!("({} bytes)", huge.len())),
            "{message}"
        );
        assert!(
            !message.contains(&"n".repeat(REPORTED_NAME_BYTES + 1)),
            "the full name leaked into the error"
        );
        assert!(message.len() <= bound, "{} bytes: {message}", message.len());

        let traversing = format!("root\\{}", "u".repeat(2000));
        let archive = archive_with(&[(traversing.as_str(), b"x", None)]);
        let message = rejection(archive.path(), limits);
        assert!(message.starts_with(&archive_rejection("unsafe archive path root\\")));
        assert!(message.len() <= bound, "{} bytes: {message}", message.len());
    }

    #[test]
    fn reported_names_are_truncated_on_character_boundaries() {
        assert_eq!(reported_name("root/file"), "root/file");

        let multibyte = format!("root/{}", "é".repeat(REPORTED_NAME_BYTES));
        let reported = reported_name(&multibyte);
        let prefix = reported.split('…').next().unwrap();

        assert!(multibyte.starts_with(prefix), "{reported}");
        assert!(prefix.len() <= REPORTED_NAME_BYTES);
        assert!(
            prefix.len() > REPORTED_NAME_BYTES - "é".len(),
            "truncation gave up more than one character: {} bytes",
            prefix.len()
        );
        assert!(reported.contains(&format!("({} bytes)", multibyte.len())));
    }

    #[test]
    fn retained_output_paths_are_capped_in_aggregate() {
        assert_eq!(
            ArchiveLimits::default().max_retained_path_bytes,
            32 * 1024 * 1024
        );
        let limits = ArchiveLimits {
            max_retained_path_bytes: 12,
            ..ArchiveLimits::default()
        };

        let at_limit = archive_with(&[("root/ab", b"1", None), ("root/cd", b"2", None)]);
        let destination = tempfile::tempdir().unwrap();
        let root = extract_zip_archive(at_limit.path(), destination.path(), limits).unwrap();
        assert_eq!(std::fs::read(root.join("cd")).unwrap(), b"2");

        let over_limit = archive_with(&[
            ("root/ab", b"1", None),
            ("root/cd", b"2", None),
            ("root/ef", b"3", None),
        ]);
        assert_eq!(
            rejection(over_limit.path(), limits),
            archive_rejection("archive paths exceed the 12 byte path retention limit")
        );
    }

    #[test]
    fn retained_paths_reject_bytes_beyond_the_limit() {
        let mut budget = RetainedPaths::new(MAX_RETAINED_PATH_BYTES);
        budget.retain(MAX_RETAINED_PATH_BYTES).unwrap();

        let error = budget.retain(1).unwrap_err();
        assert_eq!(
            error.to_string(),
            archive_rejection(&format!(
                "archive paths exceed the {MAX_RETAINED_PATH_BYTES} byte path retention limit"
            ))
        );

        let mut overflowing = RetainedPaths::new(usize::MAX);
        overflowing.retain(usize::MAX).unwrap();
        assert!(overflowing.retain(1).is_err());

        let mut copied_paths = RetainedPaths::new(4);
        copied_paths.retain_copies(2, 2).unwrap();
        assert!(copied_paths.retain_copies(1, 1).is_err());

        let mut overflowing_copies = RetainedPaths::new(usize::MAX);
        assert!(overflowing_copies.retain_copies(usize::MAX, 2).is_err());
    }

    #[test]
    fn extraction_read_limits_reject_unrepresentable_entry_sizes() {
        assert_eq!(extraction_read_limit(0).unwrap(), 1);
        assert_eq!(extraction_read_limit(u64::MAX - 1).unwrap(), u64::MAX);
        assert!(extraction_read_limit(u64::MAX).is_err());
    }

    #[test]
    fn declared_entry_limits_are_enforced_at_the_first_entry_past_the_limit() {
        assert!(enforce_declared_entry_limit(0, 0).is_ok());
        assert!(enforce_declared_entry_limit(8, 8).is_ok());
        assert!(enforce_declared_entry_limit(9, 8).is_err());
        assert!(enforce_declared_entry_limit(u64::MAX, usize::MAX - 1).is_err());
    }
    fn zip64_classic_footer(window_offset: usize) -> ClassicFooter {
        ClassicFooter {
            window_offset,
            disk_number: 0,
            disk_with_central_directory: 0,
            entries_on_disk: 0,
            total_entries: ZIP64_ENTRY_COUNT_SENTINEL,
            central_directory_size: 0,
            central_directory_offset: 0,
            comment_bytes: 0,
        }
    }

    fn zip64_locator_bytes(footer_offset: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ZIP64_LOCATOR_SIGNATURE);
        bytes.extend_from_slice(&FIRST_DISK.to_le_bytes());
        bytes.extend_from_slice(&footer_offset.to_le_bytes());
        bytes.extend_from_slice(&SINGLE_DISK.to_le_bytes());
        bytes
    }

    fn rejected<T>(result: Result<T, ReviewError>) -> ReviewError {
        match result {
            Ok(_) => panic!("the operation must be rejected"),
            Err(error) => error,
        }
    }

    #[test]
    fn archive_window_sizes_reject_bytes_beyond_the_addressable_limit() {
        assert_eq!(addressable_window_bytes(4, 4).unwrap(), 4);
        assert!(addressable_window_bytes(5, 4).is_err());
    }

    #[test]
    fn archive_rewind_failures_keep_their_operation_context() {
        let error = rewind_archive_file(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not seekable",
        )))
        .unwrap_err();

        assert!(matches!(
            error,
            ReviewError::Io { action, source }
                if action == "rewind pull request archive"
                    && source.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn trailing_metadata_reads_report_short_files() {
        let archive = archive_file(&[]);
        let mut file = archive.reopen().unwrap();

        let error = rejected(read_trailing_metadata(&mut file, 1));

        assert!(matches!(
            error,
            ReviewError::Io { action, source }
                if action == "read archive trailing metadata"
                    && source.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn zip64_resolution_without_room_for_a_locator_is_absent() {
        let archive = archive_file(&[]);
        let mut file = archive.reopen().unwrap();
        let trailer = TrailingMetadata {
            start: 0,
            bytes: Vec::new(),
        };

        let footer = resolve_zip64_footer(&mut file, &trailer, &zip64_classic_footer(19)).unwrap();

        assert!(footer.is_none());
    }

    #[test]
    fn zip64_resolution_rejects_an_unaddressable_locator() {
        let archive = archive_file(&[]);
        let mut file = archive.reopen().unwrap();
        let mut bytes = vec![0];
        bytes.extend_from_slice(&zip64_locator_bytes(0));
        let trailer = TrailingMetadata {
            start: u64::MAX,
            bytes,
        };

        let error = rejected(resolve_zip64_footer(
            &mut file,
            &trailer,
            &zip64_classic_footer(21),
        ));

        assert_eq!(
            error.to_string(),
            archive_rejection("archive trailing metadata is not addressable")
        );
    }

    #[test]
    fn zip64_resolution_reports_an_unreadable_footer_window() {
        let archive = archive_file(&[]);
        let mut file = archive.reopen().unwrap();
        let trailer = TrailingMetadata {
            start: 100,
            bytes: zip64_locator_bytes(0),
        };

        let error = rejected(resolve_zip64_footer(
            &mut file,
            &trailer,
            &zip64_classic_footer(20),
        ));

        assert!(matches!(
            error,
            ReviewError::Io { action, source }
                if action == "read archive ZIP64 end of central directory record"
                    && source.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn classic_declarations_reject_an_unaddressable_footer() {
        let trailer = TrailingMetadata {
            start: u64::MAX,
            bytes: Vec::new(),
        };
        let classic = ClassicFooter {
            window_offset: 1,
            disk_number: 0,
            disk_with_central_directory: 0,
            entries_on_disk: 0,
            total_entries: 0,
            central_directory_size: 0,
            central_directory_offset: 0,
            comment_bytes: 0,
        };

        let error = rejected(declared_central_directory(&trailer, &classic, None));

        assert_eq!(
            error.to_string(),
            archive_rejection("archive trailing metadata is not addressable")
        );
    }

    #[test]
    fn archive_inspection_rechecks_its_entry_limit() {
        let archive = archive_with(&[("root/one", b"1", None), ("root/two", b"2", None)]);
        let file = std::fs::File::open(archive.path()).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let limits = ArchiveLimits {
            max_entries: 1,
            ..ArchiveLimits::default()
        };

        let error = rejected(inspect_archive(&mut archive, limits));

        assert_eq!(
            error.to_string(),
            archive_rejection("archive contains more than 1 entries")
        );
    }
}
