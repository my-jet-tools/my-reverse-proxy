//! A release build keeps debuggers out of the process: the files key and the network keys are in
//! its memory (see `crate::secure`), and whoever attaches a debugger, or opens the process to
//! read its memory, reads them.
//!
//! What it does, once, before the settings and the keys are read:
//! - it does not start under a debugger, and stops when one is attached later;
//! - it takes away from everybody the rights on the process which reading its memory, writing to
//!   it, or attaching to it need: the system and the administrators keep "end it" and "ask what
//!   it is", and so does the account the process runs as;
//! - it shows no crash dialog, which holds a dead process in memory for whoever clicks.
//!
//! What it can not do: an administrator has the debug privilege, which passes over the access
//! list of any process, and the kernel reads everything. This keeps out the accounts which are
//! not administrators - the process's own account as well - and it is the line Windows draws.
//!
//! A debug build does none of it, and can be debugged.

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{SetKernelObjectSecurity, DACL_SECURITY_INFORMATION};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent, SetErrorMode, SEM_FAILCRITICALERRORS,
    SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
/// SYNCHRONIZE - what `taskkill` and Task Manager open a process with - for the system (SY), the
/// administrators (BA) and the owner (OW, which without an entry of its own could rewrite this
/// list). Nobody is given the memory, a thread, or a handle of the process.
const PROCESS_ACCESS: &str = "D:P(A;;0x101401;;;SY)(A;;0x101401;;;BA)(A;;0x101401;;;OW)";

const SDDL_REVISION_1: u32 = 1;

/// The exit code of a process which found a debugger on itself.
const DEBUGGER_EXIT_CODE: i32 = 3;

const DEBUGGER_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// See the module. An error is a reason not to start.
pub fn harden_process() -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Ok(());
    }

    if debugger_is_attached() {
        return Err(
            "A debugger is attached: a release build does not run under one, as the keys in its \
             memory would be read. Debug a debug build."
                .to_string(),
        );
    }

    // SAFETY: a call which sets a flag of the process.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }

    restrict_process_access()?;

    std::thread::Builder::new()
        .name("debugger-watch".to_string())
        .spawn(|| loop {
            std::thread::sleep(DEBUGGER_CHECK_INTERVAL);

            if debugger_is_attached() {
                eprintln!("A debugger was attached to the process: stopping.");
                std::process::exit(DEBUGGER_EXIT_CODE);
            }
        })
        .map_err(|err| format!("The debugger watch can not be started: {err}"))?;

    Ok(())
}

fn debugger_is_attached() -> bool {
    let mut remote = 0;

    // SAFETY: the pseudo handle of this process, and an out pointer valid for the call.
    unsafe {
        IsDebuggerPresent() != 0
            || (CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote) != 0 && remote != 0)
    }
}

fn restrict_process_access() -> Result<(), String> {
    let sddl: Vec<u16> = PROCESS_ACCESS.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();

    // SAFETY: `sddl` is nul-terminated, and the out pointer is valid for the call.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };

    if converted == 0 {
        return Err(format!(
            "The access list of the process can not be built: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: the pseudo handle of this process has every right on it, and `descriptor` is the
    // one built above, freed after this its only use.
    let result = unsafe {
        let set =
            SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, descriptor);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor);
        (set != 0).then_some(()).ok_or(error)
    };

    result.map_err(|err| format!("The access list of the process can not be set: {err}"))
}
