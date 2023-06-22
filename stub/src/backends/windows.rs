use std::{error::Error, fs, mem, ptr};

use libnanomite::JumpDataTable;
use ntapi::{
    ntpebteb::PEB,
    ntpsapi::{NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION},
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, TRUE},
        ntdef::{HANDLE, NT_SUCCESS}, winerror::SUCCEEDED,
    },
    um::{
        debugapi::{ContinueDebugEvent, WaitForDebugEvent},
        memoryapi::ReadProcessMemory,
        processenv::GetCommandLineA,
        processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, OpenThread, SuspendThread, GetThreadContext, ResumeThread, SetThreadContext},
        synchapi::WaitForSingleObject,
        winbase::{DEBUG_PROCESS, INFINITE},
        winnt::{DBG_CONTINUE, THREAD_ALL_ACCESS, CONTEXT, CONTEXT_CONTROL, CONTEXT_FULL}, handleapi::CloseHandle,
    },
};

pub fn run(bin: &[u8], jdt: JumpDataTable) {
    if let Ok(info) = run_binary(bin) {
        run_handler(info, jdt);
    }
}

const EXCEPTION_DEBUG_EVENT: DWORD = 1;
const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;

fn run_handler(info: (PROCESS_INFORMATION, String), jdt: JumpDataTable) {
    let (pi, file_name) = info;

    let base_addr = read_remote_peb(pi.hProcess).unwrap().ImageBaseAddress as usize;

    unsafe {
        let mut debug_event = mem::zeroed();
        loop {
            WaitForDebugEvent(&mut debug_event, INFINITE);

            match debug_event.dwDebugEventCode {
                EXEPTION_DEBUG_EVENT => handle_int3(debug_event.dwThreadId, base_addr, &jdt),
                EXIT_PROCESS_DEBUG_EVENT => break,
                _ => (),
            }

            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                DBG_CONTINUE,
            );
        }

        ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            DBG_CONTINUE,
        );

        WaitForSingleObject(pi.hProcess, INFINITE);

        // Free handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        fs::remove_file(file_name).unwrap();
    }
}

unsafe fn handle_int3(thread_id: u32, base_addr: usize, jdt: &JumpDataTable) {
    // Open a handle to the thread.
    let handle = OpenThread(THREAD_ALL_ACCESS, TRUE, thread_id);

    if !SUCCEEDED(handle as i32) {
        panic!();
    }

    // GetThreadContext requires the thread is suspended. It should already be suspended, this is for redundancy.
    SuspendThread(handle);

    let mut context = mem::zeroed::<CONTEXT>();
    context.ContextFlags = CONTEXT_FULL;

    // Get the thread context.
    let ret = GetThreadContext(handle, &mut context);

    // LdrpInitializeProcess will trigger a breakpoint if the process is being debugged when it is
    // created. This function will handle that breakpoint, but GetThreadContext only allows us to
    // get the context of threads we own. Thus, if GetThreadContext fails we should just move on.
    if ret == 0 {
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jdt.get(context.Rip as usize - 1 - base_addr);

    // If there was an error getting the jump data, jump to the next instruction and hope for the
    // best.
    if jump_data.is_none() {
        context.Rip += 1;
        SetThreadContext(handle, &context);
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jump_data.unwrap();

    // Add the signed offset to RIP.
    let offset = jump_data.eval_jump(context.EFlags as u64, context.Rcx as u64);
    context.Rip = (context.Rip as i64 + offset as i64 - 1) as u64;

    // Update RIP, resume the thread, and get rid of our handle.
    SetThreadContext(handle, &context);
    ResumeThread(handle);
    CloseHandle(handle);
}

fn read_remote_peb(proc_handle: HANDLE) -> Option<PEB> {
    unsafe {
        let mut pbi = mem::zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut written = 0;

        // Get the ProcessBasicInformation to locate the address of the PEB.
        if !NT_SUCCESS(NtQueryInformationProcess(
            proc_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as _,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut written as *mut _ as _,
        )) {
            return None;
        }

        let mut peb = mem::zeroed::<PEB>();
        let mut written = 0;

        // Read the PEB.
        if ReadProcessMemory(
            proc_handle,
            pbi.PebBaseAddress as *const _,
            &mut peb as *mut _ as _,
            mem::size_of::<PEB>(),
            &mut written as *mut _ as _,
        ) == FALSE
        {
            return None;
        }

        Some(peb)
    }
}

fn run_binary(bin: &[u8]) -> Result<(PROCESS_INFORMATION, String), Box<dyn Error>> {
    // Get path to %temp%
    let temp_dir = std::env::temp_dir();

    // Create a random file name
    let file_name = format!("{}.exe", rand::random::<u32>());

    // Write the bin to that file
    let file_path = temp_dir.join(file_name).to_str().unwrap().to_string();
    std::fs::write(&file_path, bin).unwrap();

    // Create the process with the DEBUG_PROCESS flag
    unsafe {
        let mut si = mem::zeroed::<STARTUPINFOA>();
        let mut pi = mem::zeroed::<PROCESS_INFORMATION>();

        let ret = CreateProcessA(
            file_name.as_ptr() as *const _,
            GetCommandLineA(),
            ptr::null_mut(),
            ptr::null_mut(),
            TRUE,
            DEBUG_PROCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut si,
            &mut pi,
        );

        if ret == TRUE {
            Ok((pi, file_path))
        } else {
            Err("Failed to create process".into())
        }
    }
}
