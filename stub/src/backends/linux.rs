use alloc::ffi::CString;
use libnanomite::JumpDataTable;
use nix::{
    sys::{
        memfd::{memfd_create, MemFdCreateFlag},
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{fexecve, fork, write, ForkResult, Pid},
};
use procfs::process::Process;

pub fn run(bin: &[u8], jdt: JumpDataTable) {
    // Fork and debug the child
    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => {
            parent(child, jdt);
        }
        ForkResult::Child => {
            child(bin);
        }
    }
}

fn parent(pid: Pid, jdt: JumpDataTable) {
    // debug the child process
    ptrace::attach(pid).unwrap();

    let mut vaddr = None;

    // wait for breakpoints
    loop {
        let status = waitpid(pid, None).unwrap();
        dbg!(status);
        match status {
            WaitStatus::Stopped(_, Signal::SIGSEGV) => break,
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                if vaddr.is_none() {
                    vaddr = Some(parent_get_vaddr(pid));
                }
                parent_handle_breakpoint(pid, vaddr.unwrap(), &jdt);
            }
            WaitStatus::Exited(_, _) => break,
            _ => {}
        }
        ptrace::cont(pid, None).unwrap();
    }
}

fn parent_get_vaddr(pid: Pid) -> u64 {
    Process::new(pid.as_raw()).unwrap().maps().unwrap()[0]
        .address
        .0
}

fn parent_handle_breakpoint(pid: Pid, base_addr: u64, jdt: &JumpDataTable) {
    let mut regs = ptrace::getregs(pid).unwrap();
    // regs.rip -= 1;
    dbg!(regs);

    // check if the ip is in the jdt
    if let Some(nanomite) = jdt.get((regs.rip - base_addr - 1) as usize) {
        eprintln!("offset: 0x{:X}", regs.rip - base_addr - 1);
        dbg!(nanomite);
        let rip_offset = nanomite.eval_jump(regs.eflags, regs.rcx);
        dbg!(rip_offset);

        regs.rip = (regs.rip as isize + rip_offset as isize - 1) as u64;
        ptrace::setregs(pid, regs).unwrap();
    }
}

fn child(bin: &[u8]) {
    let _ = ptrace::traceme();

    let str = CString::new(b"xxx".to_vec()).unwrap();

    // creaate a new fd
    let fd = memfd_create(&str, MemFdCreateFlag::empty()).unwrap();

    dbg!(fd);

    // write the binary to the fd
    write(fd, bin).unwrap();

    let args = std::env::args()
        .filter_map(|s| CString::new(s.as_bytes()).ok())
        .collect::<Vec<_>>();

    let env = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect::<Vec<_>>();

    let _ = fexecve(fd, &args, &env);
}
