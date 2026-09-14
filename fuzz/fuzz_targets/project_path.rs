#![no_main]

use std::path::{Component, Path};

use bughunter::fuzzing::{ProjectPath, ProjectPathError};
use libfuzzer_sys::fuzz_target;

const MAX_PATH_BYTES: usize = 4 * 1024;
const WINDOWS_SEPARATOR: char = '\\';
const POSIX_SEPARATOR: char = '/';
const WINDOWS_NAMESPACE_SEPARATOR: char = ':';
const CURRENT_DIRECTORY: &str = ".";
const PARENT_DIRECTORY: &str = "..";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PATH_BYTES {
        return;
    }
    let requested = String::from_utf8_lossy(data);

    let outcome = ProjectPath::parse(Path::new(requested.as_ref()));
    assert_eq!(
        outcome,
        ProjectPath::parse(Path::new(requested.as_ref())),
        "parsing {requested:?} twice produced different outcomes"
    );

    match outcome {
        Ok(project_path) => {
            assert_accepted_path_stays_inside_the_project(&project_path, &requested)
        }
        Err(error) => assert_rejection_is_explained_by_the_input(error, &requested),
    }
});

fn assert_accepted_path_stays_inside_the_project(project_path: &ProjectPath, requested: &str) {
    let path = project_path.as_path();
    assert!(
        path.is_relative(),
        "accepted {requested:?} as absolute path {path:?}"
    );
    assert!(
        path.components().next().is_some(),
        "accepted {requested:?} as an empty path"
    );
    assert!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "accepted {requested:?} with non-literal components {path:?}"
    );

    let key = project_path.key();
    assert!(!key.is_empty(), "accepted {requested:?} with an empty key");
    assert!(
        !key.contains(WINDOWS_SEPARATOR),
        "key {key:?} of {requested:?} kept a Windows separator"
    );
    assert!(
        !key.contains(WINDOWS_NAMESPACE_SEPARATOR),
        "key {key:?} of {requested:?} kept a Windows namespace separator"
    );
    assert!(
        key.split(POSIX_SEPARATOR).all(|segment| {
            !segment.is_empty() && segment != CURRENT_DIRECTORY && segment != PARENT_DIRECTORY
        }),
        "key {key:?} of {requested:?} contains a traversable segment"
    );
    assert_eq!(
        ProjectPath::parse(Path::new(&key)).as_ref(),
        Ok(project_path),
        "key {key:?} of {requested:?} does not parse back to the same path"
    );
}

fn assert_rejection_is_explained_by_the_input(error: ProjectPathError, requested: &str) {
    let normalized = requested.replace(WINDOWS_SEPARATOR, "/");
    match error {
        ProjectPathError::NonUnicode => {
            panic!("Unicode input {requested:?} was rejected as non-Unicode")
        }
        ProjectPathError::WindowsNamespace => assert!(
            requested.contains(WINDOWS_NAMESPACE_SEPARATOR),
            "{requested:?} was rejected as a Windows namespace without a namespace separator"
        ),
        ProjectPathError::Absolute => assert!(
            normalized.starts_with(POSIX_SEPARATOR),
            "{requested:?} was rejected as absolute without a root"
        ),
        ProjectPathError::ParentTraversal => assert!(
            normalized
                .split(POSIX_SEPARATOR)
                .any(|segment| segment == PARENT_DIRECTORY),
            "{requested:?} was rejected as traversal without a parent segment"
        ),
        ProjectPathError::Empty => assert!(
            normalized
                .chars()
                .all(|character| character == '.' || character == POSIX_SEPARATOR),
            "{requested:?} was rejected as empty although it names a file"
        ),
    }
}
