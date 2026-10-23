use windows::Win32::Foundation::*;
use windows::Win32::System::JobObjects::*;
use windows::core::*;

pub struct Job {
    pub handle: HANDLE,
}

impl Job {
    /// Create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and
    /// **no** `JOB_OBJECT_LIMIT_BREAKAWAY_OK`, so children cannot escape the
    /// job and the whole tree dies when our handle is closed.
    pub fn create() -> Result<Job> {
        let handle = unsafe { CreateJobObjectW(None, None)? };

        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };

        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;
        }

        Ok(Job { handle })
    }

    /// Put `process` in this job.
    ///
    /// The caller must hold the process with `PROCESS_SET_QUOTA` and
    /// `PROCESS_TERMINATE` — that is what the OS checks. A refusal (a host job
    /// that forbids nesting, a process that already exited) is reported rather
    /// than swallowed, because a caller that assumes adoption succeeded is
    /// exactly the caller that leaks a process.
    pub fn assign(&self, process: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.handle, process)? };
        Ok(())
    }

    /// Terminate every process in the job now, instead of waiting for the
    /// `KILL_ON_JOB_CLOSE` close to do it.
    pub fn terminate(&self) -> Result<()> {
        unsafe { TerminateJobObject(self.handle, 1)? };
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}
