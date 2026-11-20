mod net;

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::ptr;
use std::thread;
use std::time::Duration;

const HOSTNAME: &str = "serenity";
const PRIMARY_SHELL: &str = "/bin/nu";
const FALLBACK_SHELL: &str = "/bin/sh";

fn mount_fs(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: Option<&str>) {
    if let Err(e) = fs::create_dir_all(target) {
        eprintln!("[init] warn: mkdir {} failed: {}", target, e);
    }

    let c_source = CString::new(source).expect("valid CString");
    let c_target = CString::new(target).expect("valid CString");
    let c_fstype = CString::new(fstype).expect("valid CString");
    let c_data = data.map(|d| CString::new(d).expect("valid CString"));
    let data_ptr = c_data
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr() as *const libc::c_void);

    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            data_ptr,
        )
    };

    if rc != 0 {
        let err = io::Error::last_os_error();
        // EBUSY means already mounted (e.g. devtmpfs auto-mounted by kernel).
        if err.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("[init] warn: mount {} -> {} ({}) failed: {}", source, target, fstype, err);
        }
    }
}

fn setup_filesystems() {
    let common = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount_fs("proc", "/proc", "proc", common, None);
    mount_fs("sysfs", "/sys", "sysfs", common, None);
    mount_fs("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, Some("mode=0755"));
    mount_fs("devpts", "/dev/pts", "devpts", libc::MS_NOSUID | libc::MS_NOEXEC, Some("gid=5,mode=0620"));
    mount_fs("tmpfs", "/tmp", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777"));
    mount_fs("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=0755"));
}

fn setup_hostname() {
    let rc = unsafe {
        libc::sethostname(HOSTNAME.as_ptr() as *const libc::c_char, HOSTNAME.len())
    };
    if rc != 0 {
        eprintln!("[init] warn: sethostname failed: {}", io::Error::last_os_error());
    }
}

fn setup_environment() {
    unsafe {
        std::env::set_var("PATH", "/usr/local/bin:/usr/bin:/bin:/sbin");
        std::env::set_var("HOME", "/root");
        std::env::set_var("USER", "root");
        std::env::set_var("TERM", "xterm-256color");
        std::env::set_var("XDG_CONFIG_HOME", "/root/.config");
    }
}

fn print_banner(net_status: Option<&str>) {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "?".to_string());

    let net_line = net_status.unwrap_or("offline (no NIC)");

    println!();
    println!("====================================================");
    println!("   Serenity Linux 0.1.0 (x86_64-musl + Rust PID 1)");
    println!("   Kernel : Linux {}", kernel);
    println!("   Boot   : {}s | Shell: {}", uptime, PRIMARY_SHELL);
    println!("   Net    : {}", net_line);
    println!("====================================================");
    println!();
}

fn spawn_shell() -> io::Result<Child> {
    let shell_path = if Path::new(PRIMARY_SHELL).exists() {
        PRIMARY_SHELL
    } else if Path::new(FALLBACK_SHELL).exists() {
        FALLBACK_SHELL
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No shell found at /bin/nu or /bin/sh",
        ));
    };

    let mut cmd = Command::new(shell_path);
    if shell_path == PRIMARY_SHELL {
        cmd.arg("--login");
    }
    cmd.current_dir("/root");

    // Choose controlling terminal: /dev/ttyS0 for QEMU serial, /dev/tty1 for real hardware display.
    let use_serial = fs::read_to_string("/proc/cmdline")
        .map(|s| s.contains("console=ttyS0"))
        .unwrap_or(false);

    // Create a new session and attach a real controlling terminal so Ctrl+C, job control,
    // and interactive line editing work cleanly in Nushell on both QEMU and bare metal.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            let candidates: &[*const u8] = if use_serial {
                &[b"/dev/ttyS0\0".as_ptr(), b"/dev/console\0".as_ptr()]
            } else {
                &[
                    b"/dev/tty1\0".as_ptr(),
                    b"/dev/tty0\0".as_ptr(),
                    b"/dev/console\0".as_ptr(),
                ]
            };
            for &tty in candidates {
                let fd = libc::open(tty as *const libc::c_char, libc::O_RDWR);
                if fd >= 0 {
                    libc::dup2(fd, 0);
                    libc::dup2(fd, 1);
                    libc::dup2(fd, 2);
                    if fd > 2 {
                        libc::close(fd);
                    }
                    libc::ioctl(0, libc::TIOCSCTTY, 0);
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col == 0 {
                        ws.ws_row = 24;
                        ws.ws_col = 80;
                        libc::ioctl(0, libc::TIOCSWINSZ, &ws);
                    }
                    break;
                }
            }
            Ok(())
        });
    }

    cmd.spawn()
}

fn reap_zombies() {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
    }
}

fn handle_power_applet() -> bool {
    let argv0 = std::env::args().next().unwrap_or_default();
    let name = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    let cmd = match name {
        "poweroff" | "halt" => libc::LINUX_REBOOT_CMD_POWER_OFF,
        "reboot" => libc::LINUX_REBOOT_CMD_RESTART,
        _ => return false,
    };

    println!("[serenity] Syncing filesystems and executing {}...", name);
    unsafe {
        libc::sync();
        libc::reboot(cmd);
    }
    true
}

fn main() {
    if handle_power_applet() {
        return;
    }

    setup_filesystems();
    setup_hostname();
    setup_environment();

    let _ = fs::create_dir_all("/root");
    let net_status = net::setup_network();

    print_banner(net_status.as_deref());

    // PID 1 must never exit; exiting causes a Linux kernel panic.
    loop {
        match spawn_shell() {
            Ok(mut child) => {
                let shell_pid = child.id() as libc::pid_t;
                loop {
                    let mut status: libc::c_int = 0;
                    let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
                    if waited == shell_pid {
                        let _ = child.try_wait();
                        break;
                    }
                    if waited < 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        break;
                    }
                    reap_zombies();
                }
                println!("\n[init] Shell exited. Respawning in 1s (run 'poweroff' to shut down cleanly)...");
                thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                eprintln!("[init] error: failed to spawn shell: {}", e);
                eprintln!("[init] retrying in 3s...");
                thread::sleep(Duration::from_secs(3));
            }
        }
    }
}
