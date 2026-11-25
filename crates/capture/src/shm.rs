//! Wayland `wl_shm` shared-memory buffer pool and pixel blitting helpers.

use memmap2::MmapMut;
use std::ffi::CString;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_shm::{Format, WlShm};
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::{Dispatch, QueueHandle};

/// Shared-memory Wayland buffer backed by `memfd_create` and `wl_shm_pool`.
pub struct ShmBuffer {
    pub width: u32,
    pub height: u32,
    pub format: Format,
    pub mmap: MmapMut,
    pub buffer: WlBuffer,
    pub pool: WlShmPool,
    _fd: OwnedFd,
}

impl ShmBuffer {
    /// Allocates a shared-memory buffer with 4 bytes per pixel (`stride = width * 4`).
    pub fn new<D>(
        shm: &WlShm,
        qh: &QueueHandle<D>,
        width: u32,
        height: u32,
        format: Format,
    ) -> Result<Self, String>
    where
        D: Dispatch<WlShmPool, ()> + Dispatch<WlBuffer, ()> + 'static,
    {
        if width == 0 || height == 0 {
            return Err("cannot allocate zero-sized shm buffer".to_string());
        }
        let stride = width
            .checked_mul(4)
            .ok_or_else(|| "shm stride overflow".to_string())?;
        let byte_size = (stride as usize)
            .checked_mul(height as usize)
            .ok_or_else(|| "shm buffer size overflow".to_string())?;

        let fd = create_shm_fd(byte_size)?;
        // SAFETY: fd is valid, non-empty, and exclusively owned by this ShmBuffer.
        let mmap = unsafe {
            MmapMut::map_mut(&fd)
                .map_err(|e| format!("failed to mmap shm fd ({byte_size} bytes): {e}"))?
        };

        let pool = shm.create_pool(fd.as_fd(), byte_size as i32, qh, ());
        let buffer = pool.create_buffer(
            0,
            width as i32,
            height as i32,
            stride as i32,
            format,
            qh,
            (),
        );

        Ok(Self {
            width,
            height,
            format,
            mmap,
            buffer,
            pool,
            _fd: fd,
        })
    }

    /// Returns the mapped buffer bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.mmap
    }

    /// Returns mutable access to the mapped buffer bytes.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.mmap
    }
}

impl Drop for ShmBuffer {
    fn drop(&mut self) {
        self.buffer.destroy();
        self.pool.destroy();
    }
}

fn create_shm_fd(size: usize) -> Result<OwnedFd, String> {
    let name = CString::new("serenity-capture-shm").map_err(|e| e.to_string())?;
    let mut raw_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };

    if raw_fd < 0 {
        // Fallback to an immediately unlinked temporary file if memfd_create is unavailable.
        let pid = std::process::id();
        for attempt in 0..16 {
            let path = CString::new(format!("/tmp/.serenity-shm-{pid}-{attempt}"))
                .map_err(|e| e.to_string())?;
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                unsafe {
                    libc::unlink(path.as_ptr());
                }
                raw_fd = fd;
                break;
            }
        }
    }

    if raw_fd < 0 {
        return Err(format!(
            "failed to create shm file descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: raw_fd is newly opened and owned exclusively here.
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    loop {
        let rc = unsafe { libc::ftruncate(raw_fd, size as libc::off_t) };
        if rc == 0 {
            return Ok(owned);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("ftruncate({size}) failed: {err}"));
        }
    }
}

/// Copies a `tiny_skia::Pixmap` (premultiplied `[R, G, B, A]`) into a Wayland
/// `wl_shm::Format::Argb8888` buffer (little-endian premultiplied `[B, G, R, A]`).
pub fn blit_pixmap_to_argb8888(pixmap: &tiny_skia::Pixmap, dst: &mut [u8]) {
    let src = pixmap.data();
    let copy_len = src.len().min(dst.len());
    let pairs = src[..copy_len]
        .chunks_exact(4)
        .zip(dst[..copy_len].chunks_exact_mut(4));
    for (s, d) in pairs {
        d[0] = s[2];
        d[1] = s[1];
        d[2] = s[0];
        d[3] = s[3];
    }
}
