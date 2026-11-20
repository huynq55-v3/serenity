use std::fs::{self, File};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

const MODULES_LOAD_PATH: &str = "/etc/serenity/modules.load";

/// Loads uncompressed `.ko` kernel modules listed in `/etc/serenity/modules.load`
/// in topological order using Linux's `finit_module(2)` syscall (no external `modprobe` needed).
pub fn load_kernel_modules() -> usize {
    let content = match fs::read_to_string(MODULES_LOAD_PATH) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let mut loaded = 0;
    for line in content.lines() {
        let path_str = line.trim();
        if path_str.is_empty() || path_str.starts_with('#') {
            continue;
        }
        let path = Path::new(path_str);
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[init] kmod: cannot open {}: {}", path_str, e);
                continue;
            }
        };

        let empty_params = b"\0";
        let rc = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                file.as_raw_fd(),
                empty_params.as_ptr(),
                0 as libc::c_int,
            )
        };

        if rc == 0 {
            loaded += 1;
        } else {
            let err = io::Error::last_os_error();
            // EEXIST means module is already loaded; ignore quietly.
            if err.raw_os_error() != Some(libc::EEXIST) {
                eprintln!("[init] kmod: finit_module({}) failed: {}", path_str, err);
            }
        }
    }
    loaded
}
