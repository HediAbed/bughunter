use std::io;

#[cfg(windows)]
mod windows_jobs {
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    pub const CREATE_SUSPENDED_FLAG: u32 = CREATE_SUSPENDED;

    pub struct WindowsJob {
        handle: OwnedHandle,
    }

    impl WindowsJob {
        pub fn new() -> io::Result<Self> {
            let handle = OwnedHandle::from_nullable(unsafe {
                CreateJobObjectW(std::ptr::null(), std::ptr::null())
            })?;
            let job = Self { handle };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let limit_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| io::Error::other("Windows Job Object limits exceed u32"))?;
            let configured = unsafe {
                SetInformationJobObject(
                    job.handle(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    limit_size,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub fn assign(&self, process: *mut c_void) -> io::Result<()> {
            if unsafe { AssignProcessToJobObject(self.handle(), process) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        pub fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.handle(), 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn handle(&self) -> HANDLE {
            self.handle.handle()
        }
    }

    pub fn resume_primary_thread(process_id: u32) -> io::Result<()> {
        let thread_id = primary_thread_id(process_id)?;
        let thread =
            OwnedHandle::from_nullable(unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) })?;
        let previous_count = unsafe { ResumeThread(thread.handle()) };
        if previous_count == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if previous_count != 1 {
            return Err(io::Error::other(format!(
                "suspended process thread had suspend count {previous_count}"
            )));
        }
        Ok(())
    }

    fn primary_thread_id(process_id: u32) -> io::Result<u32> {
        let snapshot =
            OwnedHandle::from_snapshot(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>())
                .map_err(|_| io::Error::other("Windows thread entry size exceeds u32"))?,
            ..THREADENTRY32::default()
        };
        if unsafe { Thread32First(snapshot.handle(), &mut entry) } == 0 {
            return Err(snapshot_iteration_error(process_id));
        }

        let mut thread_id = None;
        loop {
            if entry.th32OwnerProcessID == process_id {
                if thread_id.replace(entry.th32ThreadID).is_some() {
                    return Err(io::Error::other(
                        "suspended process has more than one thread",
                    ));
                }
            }
            if unsafe { Thread32Next(snapshot.handle(), &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(error);
                }
                break;
            }
        }
        thread_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("suspended process {process_id} has no thread"),
            )
        })
    }

    fn snapshot_iteration_error(process_id: u32) -> io::Error {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("suspended process {process_id} has no thread"),
            )
        } else {
            error
        }
    }

    struct OwnedHandle {
        raw: usize,
    }

    impl OwnedHandle {
        fn from_nullable(handle: HANDLE) -> io::Result<Self> {
            if handle.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self {
                    raw: handle as usize,
                })
            }
        }

        fn from_snapshot(handle: HANDLE) -> io::Result<Self> {
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self {
                    raw: handle as usize,
                })
            }
        }

        fn handle(&self) -> HANDLE {
            self.raw as HANDLE
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle());
            }
        }
    }
}

pub struct ProcessGroup {
    active: bool,
    #[cfg(unix)]
    process_id: u32,
    #[cfg(windows)]
    job: windows_jobs::WindowsJob,
}

impl ProcessGroup {
    #[cfg(unix)]
    fn for_process(process_id: u32) -> Self {
        Self {
            active: true,
            process_id,
        }
    }

    #[cfg(windows)]
    fn for_job(job: windows_jobs::WindowsJob) -> Self {
        Self { active: true, job }
    }

    #[cfg(not(any(unix, windows)))]
    fn unsupported() -> Self {
        Self { active: false }
    }

    pub fn terminate(mut self) -> io::Result<()> {
        self.try_terminate()
    }

    pub fn try_terminate(&mut self) -> io::Result<()> {
        let outcome = self.terminate_active();
        if outcome.is_ok() {
            self.active = false;
        }
        outcome
    }

    fn terminate_active(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            match signal_group(self.process_id) {
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
                outcome => outcome,
            }
        }
        #[cfg(windows)]
        {
            self.job.terminate()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.active {
            let _ = self.terminate_active();
        }
    }
}

pub async fn spawn_tokio_grouped(
    command: &mut tokio::process::Command,
) -> io::Result<(tokio::process::Child, ProcessGroup)> {
    #[cfg(unix)]
    {
        command.process_group(0);
        let mut child = command.spawn()?;
        let group = process_group_for_tokio_child(&mut child).await?;
        Ok((child, group))
    }
    #[cfg(windows)]
    {
        let job = windows_jobs::WindowsJob::new()?;
        command.creation_flags(windows_jobs::CREATE_SUSPENDED_FLAG);
        let mut child = command.spawn()?;
        let registration = register_tokio_child(&job, &child);
        if let Err(error) = registration {
            let _ = job.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
        Ok((child, ProcessGroup::for_job(job)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        command
            .spawn()
            .map(|child| (child, ProcessGroup::unsupported()))
    }
}

#[cfg(unix)]
async fn process_group_for_tokio_child(
    child: &mut tokio::process::Child,
) -> io::Result<ProcessGroup> {
    let Some(process_id) = child.id() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(io::Error::other("child process identifier is unavailable"));
    };
    Ok(ProcessGroup::for_process(process_id))
}

#[cfg(windows)]
fn register_tokio_child(
    job: &windows_jobs::WindowsJob,
    child: &tokio::process::Child,
) -> io::Result<()> {
    let process_id = child
        .id()
        .ok_or_else(|| io::Error::other("child process identifier is unavailable"))?;
    let process = child
        .raw_handle()
        .ok_or_else(|| io::Error::other("child process handle is unavailable"))?;
    job.assign(process)?;
    windows_jobs::resume_primary_thread(process_id)
}

pub fn spawn_std_grouped(
    command: &mut std::process::Command,
) -> io::Result<(std::process::Child, ProcessGroup)> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
        let child = command.spawn()?;
        let group = ProcessGroup::for_process(child.id());
        Ok((child, group))
    }
    #[cfg(windows)]
    {
        spawn_std_grouped_with(command, register_std_child)
    }
    #[cfg(not(any(unix, windows)))]
    {
        command
            .spawn()
            .map(|child| (child, ProcessGroup::unsupported()))
    }
}

#[cfg(windows)]
fn spawn_std_grouped_with(
    command: &mut std::process::Command,
    register: fn(&windows_jobs::WindowsJob, &std::process::Child) -> io::Result<()>,
) -> io::Result<(std::process::Child, ProcessGroup)> {
    use std::os::windows::process::CommandExt;

    let job = windows_jobs::WindowsJob::new()?;
    command.creation_flags(windows_jobs::CREATE_SUSPENDED_FLAG);
    let mut child = command.spawn()?;
    if let Err(error) = register(&job, &child) {
        let _ = job.terminate();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok((child, ProcessGroup::for_job(job)))
}

#[cfg(windows)]
fn register_std_child(
    job: &windows_jobs::WindowsJob,
    child: &std::process::Child,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    job.assign(child.as_raw_handle())?;
    windows_jobs::resume_primary_thread(child.id())
}

pub async fn terminate_tokio(
    child: &mut tokio::process::Child,
    group: ProcessGroup,
) -> io::Result<()> {
    terminate_tokio_with(child, group, terminate_group).await
}

async fn terminate_tokio_with(
    child: &mut tokio::process::Child,
    group: ProcessGroup,
    terminate: fn(ProcessGroup) -> io::Result<()>,
) -> io::Result<()> {
    let Err(termination_error) = terminate(group) else {
        return child.wait().await.map(|_| ());
    };
    child.kill().await?;
    child.wait().await?;
    Err(termination_error)
}

pub fn terminate_std(child: &mut std::process::Child, group: ProcessGroup) -> io::Result<()> {
    terminate_std_with(child, group, terminate_group, std::process::Child::kill)
}

fn terminate_std_with(
    child: &mut std::process::Child,
    group: ProcessGroup,
    terminate: fn(ProcessGroup) -> io::Result<()>,
    kill: fn(&mut std::process::Child) -> io::Result<()>,
) -> io::Result<()> {
    let Err(termination_error) = terminate(group) else {
        return child.wait().map(|_| ());
    };
    kill(child)?;
    child.wait()?;
    Err(termination_error)
}

pub fn terminate_group(group: ProcessGroup) -> io::Result<()> {
    group.terminate()
}

pub fn try_terminate_group(group: &mut ProcessGroup) -> io::Result<()> {
    group.try_terminate()
}

#[cfg(unix)]
fn signal_group(process_id: u32) -> io::Result<()> {
    let process_id = i32::try_from(process_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process ID exceeds i32"))?;
    let result = unsafe { libc::kill(-process_id, libc::SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn process_is_alive(process_id: i32) -> bool {
    if unsafe { libc::kill(process_id, 0) } != 0 {
        return false;
    }
    std::fs::read_to_string(format!("/proc/{process_id}/stat"))
        .ok()
        .and_then(|state| {
            state
                .split_whitespace()
                .nth(2)
                .map(|process_state| process_state != "Z")
        })
        .unwrap_or(true)
}

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::time::timeout;

    const GROUP_EXIT_DEADLINE: Duration = Duration::from_secs(30);

    fn process_stops_before_deadline(process_id: i32) -> bool {
        let deadline = Instant::now() + GROUP_EXIT_DEADLINE;
        while process_is_alive(process_id) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    fn forget_group_and_fail(group: ProcessGroup) -> io::Result<()> {
        std::mem::forget(group);
        Err(io::Error::other("group termination failed"))
    }

    #[tokio::test]
    async fn terminating_a_tokio_child_kills_its_process_group() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "tail -f /dev/null & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true);
        let (mut child, group) = spawn_tokio_grouped(&mut command).await.unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let descendant = lines.next_line().await.unwrap().unwrap();
        assert!(descendant.trim().parse::<u32>().is_ok(), "{descendant}");

        terminate_tokio(&mut child, group).await.unwrap();

        let inherited_pipe = timeout(GROUP_EXIT_DEADLINE, lines.next_line()).await;
        assert!(
            matches!(inherited_pipe, Ok(Ok(None))),
            "descendant kept the inherited stdout pipe open: {inherited_pipe:?}"
        );
    }

    #[test]
    fn terminating_a_std_child_kills_its_process_group() {
        use std::io::{BufRead, Read};

        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "tail -f /dev/null & echo $!; wait"])
            .stdout(std::process::Stdio::piped());
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut descendant = String::new();
        output.read_line(&mut descendant).unwrap();
        assert!(descendant.trim().parse::<u32>().is_ok(), "{descendant}");

        terminate_std(&mut child, group).unwrap();

        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut remaining = Vec::new();
            sender.send(output.read_to_end(&mut remaining)).unwrap();
        });
        assert_eq!(
            receiver.recv_timeout(GROUP_EXIT_DEADLINE).unwrap().unwrap(),
            0,
            "a descendant kept the inherited stdout pipe open"
        );
    }

    #[test]
    fn an_owned_group_outlives_a_reaped_leader_and_kills_descendants() {
        use std::io::{BufRead, Read};

        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "tail -f /dev/null & echo $!; exit 0"])
            .stdout(std::process::Stdio::piped());
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut descendant = String::new();
        output.read_line(&mut descendant).unwrap();
        let descendant: i32 = descendant.trim().parse().unwrap();
        child.wait().unwrap();

        terminate_group(group).unwrap();

        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut remaining = Vec::new();
            sender.send(output.read_to_end(&mut remaining)).unwrap();
        });
        assert_eq!(
            receiver.recv_timeout(GROUP_EXIT_DEADLINE).unwrap().unwrap(),
            0,
            "a descendant kept the inherited stdout pipe open"
        );
        assert!(process_stops_before_deadline(descendant));
    }

    #[test]
    fn dropping_an_owned_group_kills_descendants() {
        use std::io::BufRead;

        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "tail -f /dev/null & echo $!; exit 0"])
            .stdout(std::process::Stdio::piped());
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut descendant = String::new();
        output.read_line(&mut descendant).unwrap();
        let descendant: i32 = descendant.trim().parse().unwrap();
        child.wait().unwrap();

        drop(group);

        assert!(process_stops_before_deadline(descendant));
    }

    #[test]
    fn signaling_a_missing_process_group_reports_the_operating_system_error() {
        let error = signal_group(i32::MAX as u32).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn process_group_ids_must_fit_the_operating_system_type() {
        let error = signal_group(u32::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = ProcessGroup::for_process(u32::MAX).terminate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn a_reaped_tokio_child_has_no_available_process_group() {
        let mut child = tokio::process::Command::new("true").spawn().unwrap();
        child.wait().await.unwrap();

        let Err(error) = process_group_for_tokio_child(&mut child).await else {
            panic!("a reaped child must not produce a process group");
        };

        assert_eq!(error.to_string(), "child process identifier is unavailable");
    }

    #[tokio::test]
    async fn tokio_termination_falls_back_and_reports_the_group_failure() {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        let (mut child, group) = spawn_tokio_grouped(&mut command).await.unwrap();

        let error = terminate_tokio_with(&mut child, group, forget_group_and_fail)
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "group termination failed");
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn std_termination_falls_back_and_reports_the_group_failure() {
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();

        let error = terminate_std_with(
            &mut child,
            group,
            forget_group_and_fail,
            std::process::Child::kill,
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "group termination failed");
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn std_termination_reports_a_failed_fallback_kill() {
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();

        let error = terminate_std_with(&mut child, group, forget_group_and_fail, |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::time::Duration;

    const GROUP_EXIT_DEADLINE: Duration = Duration::from_secs(30);

    #[test]
    fn a_failed_registration_cannot_run_the_suspended_child() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ran");
        let mut command = std::process::Command::new("cmd.exe");
        command.args([
            "/D",
            "/S",
            "/C",
            &format!("echo ran > {}", marker.display()),
        ]);

        let Err(error) = spawn_std_grouped_with(&mut command, |_, _| {
            Err(io::Error::other("registration failed"))
        }) else {
            panic!("a rejected registration must fail the grouped spawn");
        };

        assert_eq!(error.to_string(), "registration failed");
        assert!(!marker.exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tokio_group_terminates_descendants() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};

        let mut command = tokio::process::Command::new("cmd.exe");
        command
            .args([
                "/D",
                "/S",
                "/C",
                r#"start "" /B ping.exe -n 30 127.0.0.1 >nul & echo spawned & ping.exe -n 30 127.0.0.1 >nul"#,
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        let (mut child, group) = spawn_tokio_grouped(&mut command).await.unwrap();
        let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut first_line = String::new();
        let read = tokio::time::timeout(GROUP_EXIT_DEADLINE, output.read_line(&mut first_line))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0);
        assert_eq!(first_line.trim(), "spawned");

        terminate_tokio(&mut child, group).await.unwrap();
        let mut remaining = Vec::new();
        output.read_to_end(&mut remaining).await.unwrap();
    }

    #[test]
    fn an_owned_job_outlives_a_reaped_leader_and_kills_descendants() {
        use std::io::BufRead;

        let stage_timeout = GROUP_EXIT_DEADLINE;
        let mut command = std::process::Command::new("cmd.exe");
        command
            .args([
                "/D",
                "/S",
                "/C",
                r#"start "" /B ping.exe -n 30 127.0.0.1 & echo spawned"#,
            ])
            .stdout(Stdio::piped());
        let (mut child, group) = spawn_std_grouped(&mut command).unwrap();
        let output = std::io::BufReader::new(child.stdout.take().unwrap());

        let (reader_sender, reader) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = output;
            let mut marker = Vec::new();
            let read = output.read_until(b'\n', &mut marker);
            reader_sender
                .send(read.map(|_| marker))
                .expect("stage: marker sent");
            let mut remaining = Vec::new();
            let drained = output.read_to_end(&mut remaining);
            reader_sender
                .send(drained.map(|_| remaining))
                .expect("stage: drained sent");
        });

        let marker = reader
            .recv_timeout(stage_timeout)
            .expect("stage: marker read")
            .expect("stage: marker read ok");
        assert_eq!(String::from_utf8_lossy(&marker).trim(), "spawned");

        let (wait_sender, wait_receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            wait_sender.send(child.wait()).unwrap();
        });
        wait_receiver
            .recv_timeout(stage_timeout)
            .expect("stage: leader exit");

        assert!(matches!(
            reader.recv_timeout(Duration::from_millis(250)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        terminate_group(group).expect("stage: terminate group");

        reader
            .recv_timeout(stage_timeout)
            .expect("stage: descendant output closes")
            .expect("stage: descendant output read");
    }
}
