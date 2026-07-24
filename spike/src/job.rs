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
}

impl Drop for Job {
    fn drop(&mut self) {
        // Closing the handle triggers KILL_ON_JOB_CLOSE for the whole tree.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}
