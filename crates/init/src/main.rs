mod auth;
mod kmod;
mod net;

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

static PENDING_POWER_ACTION: AtomicI32 = AtomicI32::new(0);

extern "C" fn power_signal_handler(sig: libc::c_int) {
    PENDING_POWER_ACTION.store(sig, Ordering::SeqCst);
}

fn check_pending_power_action() {
    match PENDING_POWER_ACTION.load(Ordering::SeqCst) {
        libc::SIGUSR2 => {
            println!("\n[init] Powering off Serenity Linux...");
            unsafe {
                libc::sync();
                libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
            }
        }
        libc::SIGINT | libc::SIGUSR1 => {
            println!("\n[init] Rebooting Serenity Linux...");
            unsafe {
                libc::sync();
                libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
            }
        }
        _ => {}
    }
}

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

fn apply_security_sysctls() {
    const HARDENING_SYSCTLS: &[(&str, &str)] = &[
        ("/proc/sys/kernel/kptr_restrict", "1\n"),
        ("/proc/sys/kernel/dmesg_restrict", "1\n"),
        ("/proc/sys/kernel/yama/ptrace_scope", "1\n"),
        ("/proc/sys/kernel/unprivileged_bpf_disabled", "1\n"),
        ("/proc/sys/fs/suid_dumpable", "0\n"),
        ("/proc/sys/fs/protected_hardlinks", "1\n"),
        ("/proc/sys/fs/protected_symlinks", "1\n"),
        ("/proc/sys/fs/protected_fifos", "1\n"),
        ("/proc/sys/fs/protected_regular", "2\n"),
        ("/proc/sys/net/ipv4/tcp_syncookies", "1\n"),
        ("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", "1\n"),
        ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/default/accept_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/all/secure_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/default/secure_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/all/send_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/default/send_redirects", "0\n"),
        ("/proc/sys/net/ipv4/conf/all/accept_source_route", "0\n"),
        ("/proc/sys/net/ipv4/conf/default/accept_source_route", "0\n"),
        ("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "1\n"),
        ("/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", "1\n"),
        ("/proc/sys/net/ipv6/conf/all/accept_redirects", "0\n"),
        ("/proc/sys/net/ipv6/conf/default/accept_redirects", "0\n"),
        ("/proc/sys/net/ipv6/conf/all/accept_source_route", "0\n"),
        ("/proc/sys/net/ipv6/conf/default/accept_source_route", "0\n"),
    ];

    for (path, val) in HARDENING_SYSCTLS {
        let _ = fs::write(path, val);
    }
}

fn setup_filesystems() {
    let common = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount_fs("proc", "/proc", "proc", common, None);
    mount_fs("sysfs", "/sys", "sysfs", common, None);
    mount_fs("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, Some("mode=0755"));
    mount_fs("devpts", "/dev/pts", "devpts", libc::MS_NOSUID | libc::MS_NOEXEC, Some("gid=5,mode=0620,ptmxmode=0666"));
    mount_fs("tmpfs", "/tmp", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777"));
    mount_fs("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=0755"));
    mount_fs("tmpfs", "/dev/shm", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777"));

    for (target, link) in [
        ("/proc/self/fd", "/dev/fd"),
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
    ] {
        let _ = std::os::unix::fs::symlink(target, link);
    }

    // Allow unprivileged Linux User Namespaces so browsers (Google Chrome) run with full
    // namespace sandbox enabled even on Ubuntu kernels that default apparmor_restrict_unprivileged_userns=1.
    let _ = fs::write("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0\n");
    let _ = fs::write("/proc/sys/kernel/unprivileged_userns_clone", "1\n");

    apply_security_sysctls();
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

fn detect_drm_card() -> Option<String> {
    let entries = fs::read_dir("/dev/dri").ok()?;
    let mut cards: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("card"))
        .collect();
    cards.sort();
    cards.into_iter().next().map(|c| format!("/dev/dri/{}", c))
}

fn print_banner(net_status: Option<&str>, kmods_loaded: usize) {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "?".to_string());

    let net_line = net_status.unwrap_or("offline (no NIC)");
    let gpu_line = match detect_drm_card() {
        Some(card) => format!("{} (DRM/KMS ready)", card),
        None => "console only (no DRM card)".to_string(),
    };

    println!();
    println!("====================================================");
    println!("   Serenity Linux 0.1.0 (x86_64-musl + Rust PID 1)");
    println!("   Kernel : Linux {}", kernel);
    println!("   Boot   : {}s | Shell: {} | KMods: {}", uptime, PRIMARY_SHELL, kmods_loaded);
    println!("   Net    : {}", net_line);
    println!("   GPU    : {}", gpu_line);
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
                    // Arg 1 = force-acquire controlling TTY as root so /dev/tty works in Nushell.
                    libc::ioctl(0, libc::TIOCSCTTY, 1);
                    let pid = libc::getpid();
                    libc::tcsetpgrp(0, pid);
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col == 0 {
                        ws.ws_row = 24;
                        ws.ws_col = 80;
                        libc::ioctl(0, libc::TIOCSWINSZ, &ws);
                    }
                    // Verify /dev/tty is actually bound; otherwise try the next candidate.
                    let check_tty = libc::open(b"/dev/tty\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
                    if check_tty >= 0 {
                        libc::close(check_tty);
                        break;
                    }
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

fn handle_multicall_applet() -> bool {
    let argv0 = std::env::args().next().unwrap_or_default();
    let name = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    match name {
        "poweroff" | "halt" => {
            println!("[serenity] Syncing filesystems and executing {}...", name);
            unsafe {
                libc::sync();
                if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) != 0 {
                    // Non-root user (UID 1000 inside Alacritty/COSMIC): ask PID 1 to power off
                    libc::kill(1, libc::SIGUSR2);
                }
            }
            true
        }
        "reboot" => {
            println!("[serenity] Syncing filesystems and executing reboot...");
            unsafe {
                libc::sync();
                if libc::reboot(libc::LINUX_REBOOT_CMD_RESTART) != 0 {
                    // Non-root user (UID 1000 inside Alacritty/COSMIC): ask PID 1 to reboot
                    libc::kill(1, libc::SIGUSR1);
                }
            }
            true
        }
        "sudo" => auth::run_sudo_applet(),
        "passwd" => auth::run_passwd_applet(),
        "suspend" => {
            println!("[serenity] Syncing filesystems and entering sleep (suspend-to-RAM)...");
            unsafe { libc::sync(); }
            if let Err(e) = fs::write("/sys/power/state", "mem")
                .or_else(|_| fs::write("/sys/power/state", "freeze"))
            {
                eprintln!("[serenity] suspend failed: {}", e);
                std::process::exit(1);
            }
            true
        }
        "cosmic-osd" => {
            let action = std::env::args().nth(1).unwrap_or_default();
            match action.as_str() {
                "shutdown" => unsafe {
                    libc::sync();
                    if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) != 0 {
                        libc::kill(1, libc::SIGUSR2);
                    }
                },
                "restart" => unsafe {
                    libc::sync();
                    if libc::reboot(libc::LINUX_REBOOT_CMD_RESTART) != 0 {
                        libc::kill(1, libc::SIGUSR1);
                    }
                },
                "suspend" => {
                    unsafe { libc::sync(); }
                    let _ = fs::write("/sys/power/state", "mem")
                        .or_else(|_| fs::write("/sys/power/state", "freeze"));
                }
                "log-out" => {
                    let _ = Command::new("/bin/kill")
                        .args(["-TERM", "-1"])
                        .status();
                }
                _ => {}
            }
            true
        }
        "start-desktop" => {
            // Ensure multicall symlinks for cosmic-applets exist whenever cosmic-applets is installed
            if Path::new("/usr/bin/cosmic-applets").exists() {
                for applet in [
                    "cosmic-app-list",
                    "cosmic-applet-audio",
                    "cosmic-applet-battery",
                    "cosmic-applet-time",
                    "cosmic-applet-power",
                    "cosmic-applet-network",
                    "cosmic-applet-notifications",
                    "cosmic-applet-minimize",
                    "cosmic-panel-button",
                ] {
                    let link = format!("/usr/bin/{}", applet);
                    if !Path::new(&link).exists() {
                        let _ = std::os::unix::fs::symlink("cosmic-applets", &link);
                    }
                }
            }

            // Start System D-Bus (/run/dbus/system_bus_socket & /var/run/dbus/system_bus_socket)
            // + serenity-sysd (login1 SetBrightness/PowerOff + UPower)
            // + wpa_supplicant + NetworkManager (so cosmic-applet-network lists & connects Wi-Fi)
            let _ = fs::create_dir_all("/run/dbus");
            let _ = fs::create_dir_all("/var");
            if !Path::new("/var/run").exists() {
                let _ = std::os::unix::fs::symlink("/run", "/var/run");
            }
            let fresh_system_bus = !Path::new("/run/dbus/system_bus_socket").exists();
            if Path::new("/usr/bin/dbus-daemon").exists() && fresh_system_bus {
                println!("[serenity] Starting System D-Bus daemon...");
                let _ = Command::new("/usr/bin/dbus-daemon")
                    .args(["--system", "--fork", "--nopidfile"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                for _ in 0..20 {
                    if Path::new("/run/dbus/system_bus_socket").exists() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
            if fresh_system_bus
                && Path::new("/usr/bin/serenity-sysd").exists()
                && Path::new("/run/dbus/system_bus_socket").exists()
            {
                println!("[serenity] Starting serenity-sysd (login1 + UPower)...");
                let _ = Command::new("/usr/bin/serenity-sysd")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                // Brief settle so org.freedesktop.login1 & org.freedesktop.UPower register on D-Bus
                // before cosmic-settings-daemon and cosmic-applet-battery connect.
                thread::sleep(Duration::from_millis(250));
            }
            if fresh_system_bus
                && Path::new("/usr/bin/wpa_supplicant").exists()
                && Path::new("/run/dbus/system_bus_socket").exists()
            {
                let _ = fs::create_dir_all("/run/wpa_supplicant");
                let wpa_log = fs::File::create("/tmp/wpa_supplicant.log")
                    .map(std::process::Stdio::from)
                    .unwrap_or_else(|_| std::process::Stdio::null());
                let wpa_err = fs::File::create("/tmp/wpa_supplicant.log")
                    .map(std::process::Stdio::from)
                    .unwrap_or_else(|_| std::process::Stdio::null());
                let _ = Command::new("/usr/bin/wpa_supplicant")
                    .args(["-u", "-O", "/run/wpa_supplicant"])
                    .stdin(std::process::Stdio::null())
                    .stdout(wpa_log)
                    .stderr(wpa_err)
                    .spawn();
            }
            if fresh_system_bus
                && Path::new("/usr/bin/NetworkManager").exists()
                && Path::new("/run/dbus/system_bus_socket").exists()
            {
                println!("[serenity] Starting NetworkManager (Wi-Fi & Ethernet)...");
                let _ = fs::create_dir_all("/var/lib/NetworkManager");
                let _ = fs::create_dir_all("/etc/NetworkManager/system-connections");
                let _ = fs::create_dir_all("/etc/netplan");
                let _ = fs::create_dir_all("/run/NetworkManager/system-connections");
                if !Path::new("/etc/machine-id").exists() {
                    let _ = fs::write("/etc/machine-id", "5e7e1170a1b2c3d4e5f60718293a4b5c\n");
                }
                let nm_log = fs::File::create("/tmp/networkmanager.log")
                    .map(std::process::Stdio::from)
                    .unwrap_or_else(|_| std::process::Stdio::null());
                let nm_err = fs::File::create("/tmp/networkmanager.log")
                    .map(std::process::Stdio::from)
                    .unwrap_or_else(|_| std::process::Stdio::null());
                let _ = Command::new("/usr/bin/NetworkManager")
                    .args(["--no-daemon", "--debug", "--log-level=INFO"])
                    .stdin(std::process::Stdio::null())
                    .stdout(nm_log)
                    .stderr(nm_err)
                    .spawn();
            }

            // Start seatd (as root) before dropping privileges so non-root Wayland compositors
            // like cosmic-comp can securely access DRM/KMS and input devices via libseat.
            if Path::new("/usr/bin/seatd").exists() && !Path::new("/run/seatd.sock").exists() {
                println!("[serenity] Starting seatd daemon (-g video)...");
                let _ = Command::new("/usr/bin/seatd")
                    .args(["-g", "video"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                for _ in 0..20 {
                    if Path::new("/run/seatd.sock").exists() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }

            setup_desktop_permissions();

            println!("[serenity] Dropping privileges to user 'serenity' (UID 1000)...");
            let groups: [libc::gid_t; 5] = [1000, 29, 44, 104, 107]; // serenity, audio, video, input, render
            unsafe {
                let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_CORE, &rl);
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                    eprintln!("[serenity] setgroups failed: {}", io::Error::last_os_error());
                    std::process::exit(1);
                }
                if libc::setgid(1000) != 0 || libc::setuid(1000) != 0 {
                    eprintln!("[serenity] failed to drop root privileges: {}", io::Error::last_os_error());
                    std::process::exit(1);
                }
                std::env::set_var("HOME", "/home/serenity");
                std::env::set_var("USER", "serenity");
                std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
                std::env::set_var("XDG_CONFIG_HOME", "/home/serenity/.config");
                std::env::set_var("XDG_CACHE_HOME", "/home/serenity/.cache");
                std::env::set_var("XDG_DATA_HOME", "/home/serenity/.local/share");
                std::env::set_var("XDG_STATE_HOME", "/home/serenity/.local/state");
                std::env::set_var("XDG_SESSION_TYPE", "wayland");
                std::env::set_var("XDG_DATA_DIRS", "/usr/local/share:/usr/share");
                std::env::set_var("XDG_CONFIG_DIRS", "/etc/xdg:/usr/share");
                if Path::new("/run/seatd.sock").exists() {
                    std::env::set_var("LIBSEAT_BACKEND", "seatd");
                }
            }
            let extra_args: Vec<String> = std::env::args().skip(1).collect();
            let err = if !extra_args.is_empty() {
                Command::new(&extra_args[0])
                    .args(&extra_args[1..])
                    .current_dir("/home/serenity")
                    .exec()
            } else if Path::new("/usr/bin/cosmic-session").exists() {
                println!("[serenity] Launching COSMIC Desktop (cosmic-session)...");
                let bus_addr = "unix:path=/run/user/1000/bus";
                unsafe {
                    std::env::set_var("XDG_CURRENT_DESKTOP", "COSMIC");
                    std::env::set_var("XDG_SESSION_DESKTOP", "COSMIC");
                    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", bus_addr);
                }
                // Start D-Bus session bus at /run/user/1000/bus if not already running
                let _ = fs::remove_file("/run/user/1000/bus");
                if Path::new("/usr/bin/dbus-daemon").exists() {
                    let _ = Command::new("/usr/bin/dbus-daemon")
                        .args(["--session", &format!("--address={}", bus_addr), "--fork"])
                        .status();
                }
                // Start PipeWire -> WirePlumber -> PipeWire-Pulse user audio stack if installed.
                // Ordering matters: WirePlumber must register real ALSA sinks before pipewire-pulse
                // exposes the PulseAudio socket to apps like Chrome, preventing Dummy Output lock-in.
                if Path::new("/usr/bin/pipewire").exists() {
                    unmute_alsa_on_first_boot();
                    spawn_logged_daemon("/usr/bin/pipewire", "/tmp/pipewire.log");
                    for _ in 0..40 {
                        if Path::new("/run/user/1000/pipewire-0").exists() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                    if Path::new("/usr/bin/wireplumber").exists() {
                        spawn_logged_daemon("/usr/bin/wireplumber", "/tmp/wireplumber.log");
                        thread::sleep(Duration::from_millis(250));
                    }
                    if Path::new("/usr/bin/pipewire-pulse").exists() {
                        spawn_logged_daemon("/usr/bin/pipewire-pulse", "/tmp/pipewire-pulse.log");
                    }
                }
                Command::new("/usr/bin/cosmic-session")
                    .current_dir("/home/serenity")
                    .exec()
            } else if Path::new("/usr/bin/cosmic-comp").exists() {
                println!("[serenity] Launching COSMIC Compositor (cosmic-comp)...");
                unsafe {
                    std::env::set_var("XDG_CURRENT_DESKTOP", "COSMIC");
                }
                Command::new("/usr/bin/cosmic-comp")
                    .current_dir("/home/serenity")
                    .exec()
            } else {
                println!("[serenity] COSMIC not installed yet (run 'spkg install cosmic-desktop').");
                println!("[serenity] Falling back to built-in Smithay compositor + Login...");
                Command::new("/usr/bin/serenity-compositor")
                    .args(["--", "/usr/bin/serenity-login"])
                    .current_dir("/home/serenity")
                    .exec()
            };
            eprintln!("[serenity] failed to launch desktop session: {}", err);
            std::process::exit(1);
        }
        _ => false,
    }
}

fn spawn_logged_daemon(bin: &str, log_path: &str) {
    let (stdout, stderr) = match fs::File::create(log_path) {
        Ok(out) => {
            let err = out
                .try_clone()
                .map(std::process::Stdio::from)
                .unwrap_or_else(|_| std::process::Stdio::null());
            (std::process::Stdio::from(out), err)
        }
        Err(_) => (std::process::Stdio::null(), std::process::Stdio::null()),
    };
    let _ = Command::new(bin)
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn();
}

fn unmute_alsa_on_first_boot() {
    if Path::new("/home/serenity/.local/state/wireplumber/default-routes").exists()
        || !Path::new("/usr/bin/amixer").exists()
    {
        return;
    }
    let Ok(entries) = fs::read_dir("/sys/class/sound") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        let Some(idx_str) = name_str.strip_prefix("card") else { continue };
        if idx_str.parse::<u32>().is_err() {
            continue;
        }
        let _ = Command::new("/usr/bin/amixer")
            .args(["-c", idx_str, "sset", "Master", "80%", "unmute"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn setup_desktop_permissions() {
    // Prepare non-root user directories (/home/serenity and XDG_RUNTIME_DIR=/run/user/1000)
    // and grant group access on /dev/dri/* (video=44) and /dev/input/* (input=104)
    // so Smithay compositor runs as regular user UID 1000 instead of root.
    let _ = fs::create_dir_all("/home/serenity");
    let _ = fs::create_dir_all("/run/user/1000");
    let _ = fs::create_dir_all("/tmp/.X11-unix");
    unsafe {
        for dir in [b"/home/serenity\0".as_ptr(), b"/run/user/1000\0".as_ptr()] {
            libc::chown(dir as *const libc::c_char, 1000, 1000);
        }
        libc::chmod(b"/run/user/1000\0".as_ptr() as *const libc::c_char, 0o700);
        libc::chmod(b"/tmp/.X11-unix\0".as_ptr() as *const libc::c_char, 0o1777);
        // Allow non-root terminal emulators (Alacritty) to allocate PTYs via /dev/ptmx
        libc::chmod(b"/dev/ptmx\0".as_ptr() as *const libc::c_char, 0o666);
        libc::chmod(b"/dev/pts/ptmx\0".as_ptr() as *const libc::c_char, 0o666);
    }

    for (dir_path, gid) in [("/dev/dri", 44u32), ("/dev/input", 104u32)] {
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    continue;
                }
                if let Ok(c_path) = CString::new(entry.path().to_string_lossy().as_bytes()) {
                    unsafe {
                        libc::chown(c_path.as_ptr(), 0, gid);
                        libc::chmod(c_path.as_ptr(), 0o660);
                    }
                }
            }
        }
    }

    kmod::setup_sound_devices();

    // Grant video group (gid 44) write access to /sys/class/backlight/*/brightness as fallback
    // and tag backlight devices in /run/udev/data/+backlight:<name> so libudev / cosmic-settings-daemon
    // discovers intel_backlight without running systemd-udevd.
    if let Ok(entries) = fs::read_dir("/sys/class/backlight") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let b_path = entry.path().join("brightness");
            if let Ok(c_path) = CString::new(b_path.to_string_lossy().as_bytes()) {
                unsafe {
                    libc::chown(c_path.as_ptr(), 0, 44);
                    libc::chmod(c_path.as_ptr(), 0o664);
                }
            }
            if let Some(name_str) = name.to_str() {
                let udev_data = format!(
                    "E:ID_SEAT=seat0\nE:ID_FOR_SEAT=backlight-{}\nG:seat\n",
                    name_str
                );
                let _ = fs::write(format!("/run/udev/data/+backlight:{}", name_str), udev_data);
            }
        }
    }

    // Populate minimal /run/udev/data/c<major>:<minor> tags so libinput recognizes
    // keyboards, mice, touchpads, and QEMU virtio-tablet without running a full udevd daemon.
    let _ = fs::create_dir_all("/run/udev/data");
    if let Ok(entries) = fs::read_dir("/sys/class/input") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if !name_str.starts_with("event") {
                continue;
            }
            let sys_base = entry.path();
            let Ok(dev_num) = fs::read_to_string(sys_base.join("dev")) else { continue };
            let dev_num = dev_num.trim();
            let ev_hex = fs::read_to_string(sys_base.join("device/capabilities/ev"))
                .unwrap_or_default();
            let ev_bits = u64::from_str_radix(ev_hex.trim(), 16).unwrap_or(0);

            let mut udev_data = String::from("E:ID_INPUT=1\nE:ID_SEAT=seat0\nG:seat\n");
            if (ev_bits & (1 << 1)) != 0 {
                udev_data.push_str("E:ID_INPUT_KEY=1\nE:ID_INPUT_KEYBOARD=1\n");
            }
            if (ev_bits & (1 << 2)) != 0 || (ev_bits & (1 << 3)) != 0 {
                udev_data.push_str("E:ID_INPUT_MOUSE=1\n");
            }
            let _ = fs::write(format!("/run/udev/data/c{}", dev_num), udev_data);
        }
    }

    // Tag network interfaces (/sys/class/net/*) in /run/udev/data/n<ifindex> with NM_UNMANAGED=0
    // so NetworkManager marks wlan0 / eth0 as managed without running systemd-udevd.
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if name_str == "lo" {
                continue;
            }
            let Ok(ifindex) = fs::read_to_string(entry.path().join("ifindex")) else { continue };
            let ifindex = ifindex.trim();
            let udev_data = format!("E:NM_UNMANAGED=0\nE:ID_NET_NAME={}\n", name_str);
            let _ = fs::write(format!("/run/udev/data/n{}", ifindex), udev_data);
        }
    }

    // Tag DRM GPU devices (/sys/class/drm/card*) with seat0 so cosmic-comp's UdevBackend
    // discovers the GPU and its display outputs without running a full systemd-udevd daemon.
    if let Ok(entries) = fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if !name_str.starts_with("card") || name_str.contains('-') {
                continue;
            }
            let Ok(dev_num) = fs::read_to_string(entry.path().join("dev")) else { continue };
            let dev_num = dev_num.trim();
            let udev_data = format!(
                "E:ID_SEAT=seat0\nE:ID_FOR_SEAT=drm-{}\nG:seat\nG:master-of-seat\n",
                name_str
            );
            let _ = fs::write(format!("/run/udev/data/c{}", dev_num), udev_data);
        }
    }
}

fn spawn_and_wait_desktop() {
    if let Ok(mut desktop) = Command::new("/usr/bin/start-desktop").spawn() {
        let desktop_pid = desktop.id() as libc::pid_t;
        loop {
            check_pending_power_action();
            let mut status: libc::c_int = 0;
            let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
            check_pending_power_action();
            if waited == desktop_pid {
                let _ = desktop.try_wait();
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
    }
}

fn main() {
    if handle_multicall_applet() {
        return;
    }

    unsafe {
        // Disable core dumps system-wide so crashing processes don't litter ~/core.*
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);

        // Install signal handlers on PID 1 for SIGUSR1 (reboot), SIGUSR2 (poweroff),
        // and SIGINT (Ctrl+Alt+Del from kernel when reboot(CAD_OFF) is set).
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = power_signal_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0; // Do not SA_RESTART so waitpid wakes up immediately with EINTR
        libc::sigaction(libc::SIGUSR1, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGUSR2, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, ptr::null_mut());
        libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF);
    }

    setup_filesystems();
    setup_hostname();
    setup_environment();

    let _ = fs::create_dir_all("/root");
    // Drivers: kmod coldplug (modalias -> modules.alias) + uevent hotplug when the
    // `linux` + `kmod` packages are installed; otherwise legacy modules.load list.
    let uevent_sock = kmod::open_uevent_socket();
    let use_modprobe = kmod::modprobe_available();
    let kmods_loaded = if use_modprobe {
        kmod::set_kernel_modprobe_helper();
        kmod::coldplug()
    } else {
        kmod::load_kernel_modules()
    };
    if use_modprobe {
        if let Some(sock) = uevent_sock {
            kmod::spawn_hotplug_thread(sock);
        }
        // GPU & audio drivers probe asynchronously (firmware load); give them time before seat setup.
        kmod::wait_for_gpu(3000);
        kmod::wait_for_sound(2000);
    }
    if kmods_loaded > 0 {
        // Brief settle time for Wi-Fi / DRM device nodes after module load.
        thread::sleep(Duration::from_millis(400));
    }
    setup_desktop_permissions();
    let net_status = net::setup_network();

    print_banner(net_status.as_deref(), kmods_loaded);

    // Auto-launch COSMIC Desktop immediately on graphical boot (bare metal or QEMU GUI)
    // when a DRM GPU is present, cosmic-session is installed, and we are not on serial console.
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let is_serial = cmdline.contains("console=ttyS0");
    let disable_autostart = cmdline.contains("serenity.nogui");
    if !is_serial
        && !disable_autostart
        && detect_drm_card().is_some()
        && Path::new("/usr/bin/cosmic-session").exists()
    {
        if auth::has_password("serenity") {
            loop {
                check_pending_power_action();
                auth::tty_login_gate("serenity", check_pending_power_action);
                check_pending_power_action();
                println!("[init] Authenticated. Starting COSMIC Desktop...");
                spawn_and_wait_desktop();
                check_pending_power_action();
                println!("\n[init] COSMIC Desktop exited. Returning to login prompt...");
                thread::sleep(Duration::from_millis(500));
            }
        } else {
            println!("[init] No password set for 'serenity' (run 'passwd' after login to enable TTY login & sudo protection).");
            println!("[init] Auto-starting COSMIC Desktop (pass 'serenity.nogui' on kernel cmdline to stay in TTY)...");
            spawn_and_wait_desktop();
            check_pending_power_action();
            println!("\n[init] COSMIC Desktop exited. Falling back to Nushell...");
        }
    }

    // PID 1 must never exit; exiting causes a Linux kernel panic.
    loop {
        check_pending_power_action();
        if !is_serial {
            if auth::has_password("root") {
                auth::tty_login_gate("root", check_pending_power_action);
            } else if auth::has_password("serenity") {
                auth::tty_login_gate("serenity", check_pending_power_action);
            }
        }
        check_pending_power_action();
        match spawn_shell() {
            Ok(mut child) => {
                let shell_pid = child.id() as libc::pid_t;
                loop {
                    check_pending_power_action();
                    let mut status: libc::c_int = 0;
                    let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
                    check_pending_power_action();
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
                check_pending_power_action();
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
