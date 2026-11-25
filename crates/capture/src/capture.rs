//! Wayland `ext-image-copy-capture-v1`, output, and toplevel window discovery client.

use crate::shm::ShmBuffer;
use std::collections::HashMap;
use std::fs;
use std::io::BufWriter;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use wayland_client::backend::ObjectId;
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_output::{self, WlOutput};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_shm::{Format as ShmFormat, WlShm};
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::{event_created_child, Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};
use wayland_protocols::ext::image_capture_source::v1::client::{
    ext_foreign_toplevel_image_capture_source_manager_v1::ExtForeignToplevelImageCaptureSourceManagerV1,
    ext_image_capture_source_v1::ExtImageCaptureSourceV1,
    ext_output_image_capture_source_manager_v1::ExtOutputImageCaptureSourceManagerV1,
};
use wayland_protocols::ext::image_copy_capture::v1::client::{
    ext_image_copy_capture_frame_v1::{self, ExtImageCopyCaptureFrameV1, FailureReason},
    ext_image_copy_capture_manager_v1::{ExtImageCopyCaptureManagerV1, Options as CaptureOptions},
    ext_image_copy_capture_session_v1::{self, ExtImageCopyCaptureSessionV1},
};
use wayland_protocols::xdg::xdg_output::zv1::client::{
    zxdg_output_manager_v1::ZxdgOutputManagerV1,
    zxdg_output_v1::{self, ZxdgOutputV1},
};

/// Metadata describing a connected Wayland display output.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub name: String,
    pub logical_w: i32,
    pub logical_h: i32,
    pub mode_w: i32,
    pub mode_h: i32,
}

/// Metadata describing an open top-level window advertised via `ext_foreign_toplevel_list_v1`.
#[derive(Debug, Clone)]
pub struct ToplevelInfo {
    pub identifier: String,
    pub title: String,
    pub app_id: String,
}

/// Pixel rectangle in either logical surface coordinates or buffer coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

/// Capture target for screenshots and recordings.
#[derive(Debug, Clone)]
pub enum CaptureTarget {
    Output {
        output_name: Option<String>,
        crop: Option<Rect>,
    },
    Window {
        identifier: String,
    },
}

/// Byte ordering of 4-byte captured pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelLayout {
    /// `[B, G, R, X/A]` (Wayland `Xrgb8888` / `Argb8888`, FFmpeg `bgr0`).
    Bgrx,
    /// `[R, G, B, X/A]` (Wayland `Xbgr8888` / `Abgr8888`, FFmpeg `rgb0`).
    Rgbx,
}

impl PixelLayout {
    /// Returns the matching FFmpeg `-pixel_format` input name.
    pub fn ffmpeg_pix_fmt(self) -> &'static str {
        match self {
            PixelLayout::Bgrx => "bgr0",
            PixelLayout::Rgbx => "rgb0",
        }
    }
}

/// Single captured frame buffer in normalized top-down row-major pixel layout.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub layout: PixelLayout,
    pub data: Vec<u8>,
}

/// Stream format negotiated with `ext-image-copy-capture-v1`.
#[derive(Debug, Clone, Copy)]
pub struct StreamMeta {
    pub width: u32,
    pub height: u32,
    pub layout: PixelLayout,
}

/// Latest frame shared between the Wayland capture thread and the FFmpeg pacer thread.
#[derive(Debug)]
pub struct SharedFrame {
    pub seq: u64,
    pub data: Vec<u8>,
}

/// Dispatches pending Wayland events and polls the socket for up to `timeout_ms`.
pub fn poll_dispatch_once<T>(
    conn: &Connection,
    eq: &mut EventQueue<T>,
    state: &mut T,
    timeout_ms: i32,
) -> Result<(), String> {
    eq.dispatch_pending(state)
        .map_err(|e| format!("wayland dispatch error: {e}"))?;
    conn.flush()
        .map_err(|e| format!("wayland flush error: {e}"))?;

    if let Some(guard) = eq.prepare_read() {
        let raw_fd = guard.connection_fd().as_raw_fd();
        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 && (pfd.revents & libc::POLLIN) != 0 {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(ref err))
                    if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("wayland socket read failed: {e}")),
            }
        } else {
            drop(guard);
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(format!("wayland poll failed: {err}"));
                }
            }
        }
        eq.dispatch_pending(state)
            .map_err(|e| format!("wayland dispatch error: {e}"))?;
    }
    Ok(())
}

/// Maps a selection rectangle in logical surface coordinates `(surf_w, surf_h)` into clamped
/// capture buffer coordinates `(buf_w, buf_h)`. When `align_even` is true, width and height are
/// rounded down to even dimensions (`>= 2` if possible) for H.264 `yuv420p` compatibility.
pub fn map_logical_rect_to_buffer(
    rect: Rect,
    surf_w: u32,
    surf_h: u32,
    buf_w: u32,
    buf_h: u32,
    align_even: bool,
) -> Rect {
    if buf_w == 0 || buf_h == 0 || surf_w == 0 || surf_h == 0 {
        return Rect {
            x: 0,
            y: 0,
            w: buf_w,
            h: buf_h,
        };
    }

    let scale_x = buf_w as f64 / surf_w as f64;
    let scale_y = buf_h as f64 / surf_h as f64;

    let mut x = ((rect.x.max(0) as f64) * scale_x).round() as u32;
    let mut y = ((rect.y.max(0) as f64) * scale_y).round() as u32;
    let mut w = ((rect.w.max(1) as f64) * scale_x).round() as u32;
    let mut h = ((rect.h.max(1) as f64) * scale_y).round() as u32;

    let min_dim = if align_even { 2 } else { 1 };
    if buf_w >= min_dim {
        x = x.min(buf_w - min_dim);
        w = w.clamp(min_dim, buf_w - x);
        if align_even {
            w &= !1;
            if w < 2 {
                w = 2;
            }
        }
    } else {
        x = 0;
        w = buf_w;
    }

    if buf_h >= min_dim {
        y = y.min(buf_h - min_dim);
        h = h.clamp(min_dim, buf_h - y);
        if align_even {
            h &= !1;
            if h < 2 {
                h = 2;
            }
        }
    } else {
        y = 0;
        h = buf_h;
    }

    Rect {
        x: x as i32,
        y: y as i32,
        w,
        h,
    }
}

fn align_dimensions(w: u32, h: u32, align_even: bool) -> (u32, u32) {
    if !align_even {
        return (w.max(1), h.max(1));
    }
    let ew = if w >= 2 { (w & !1).max(2) } else { w.max(1) };
    let eh = if h >= 2 { (h & !1).max(2) } else { h.max(1) };
    (ew, eh)
}

/// Discovers connected outputs and open toplevel windows on the active Wayland compositor.
pub fn discover_environment() -> Result<(Vec<OutputInfo>, Vec<ToplevelInfo>), String> {
    let conn = Connection::connect_to_env()
        .map_err(|e| format!("failed to connect to Wayland display: {e}"))?;
    let mut eq = conn.new_event_queue();
    let qh = eq.handle();

    let mut state = WaylandCaptureState::default();
    let _registry = conn.display().get_registry(&qh, ());
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 1 failed: {e}"))?;

    // Request xdg_output details for every bound wl_output.
    if let Some(xdg_mgr) = state.xdg_output_mgr.clone() {
        for out in &mut state.outputs {
            let xdg_out = xdg_mgr.get_xdg_output(&out.proxy, &qh, out.global_name);
            out.xdg_output = Some(xdg_out);
        }
    }
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 2 failed: {e}"))?;

    let outputs = state
        .outputs
        .iter()
        .map(|o| {
            let logical_w = if o.logical_w > 0 { o.logical_w } else { o.mode_w };
            let logical_h = if o.logical_h > 0 { o.logical_h } else { o.mode_h };
            OutputInfo {
                name: o.name.clone(),
                logical_w,
                logical_h,
                mode_w: o.mode_w,
                mode_h: o.mode_h,
            }
        })
        .collect();

    let toplevels = state
        .toplevels
        .iter()
        .filter(|t| !t.closed && !t.identifier.is_empty())
        .map(|t| ToplevelInfo {
            identifier: t.identifier.clone(),
            title: if t.title.is_empty() {
                t.app_id.clone()
            } else {
                t.title.clone()
            },
            app_id: t.app_id.clone(),
        })
        .collect();

    if let Some(list) = state.toplevel_list.take() {
        list.stop();
        let _ = eq.roundtrip(&mut state);
    }

    Ok((outputs, toplevels))
}

/// Captures a single frame from the requested output (optionally cropped) or toplevel window.
pub fn capture_single_frame(
    target: &CaptureTarget,
    show_pointer: bool,
) -> Result<CapturedFrame, String> {
    let (conn, mut eq, qh, mut state, source) = connect_and_create_source(target)?;
    let opts = if show_pointer {
        CaptureOptions::PaintCursors
    } else {
        CaptureOptions::empty()
    };
    let capture_mgr = state
        .capture_mgr
        .clone()
        .ok_or_else(|| "compositor does not expose ext_image_copy_capture_manager_v1".to_string())?;
    let session = capture_mgr.create_session(&source, opts, &qh, ());
    state.session_done = false;
    state.session_stopped = false;

    while !state.session_done && !state.session_stopped {
        eq.blocking_dispatch(&mut state)
            .map_err(|e| format!("wayland dispatch error waiting for capture session: {e}"))?;
    }
    if state.session_stopped {
        return Err("capture session stopped before sending buffer constraints".to_string());
    }

    let shm = state
        .shm
        .clone()
        .ok_or_else(|| "compositor does not expose wl_shm".to_string())?;

    let mut shm_buf: Option<ShmBuffer> = None;

    for attempt in 0..4 {
        let (buf_w, buf_h) = state
            .buffer_size
            .ok_or_else(|| "capture session did not provide buffer_size".to_string())?;
        let (fmt, current_layout) = choose_shm_format(&state.shm_formats)
            .ok_or_else(|| "compositor did not advertise a supported 32-bit wl_shm format".to_string())?;

        let needs_alloc = shm_buf
            .as_ref()
            .map(|b| b.width != buf_w || b.height != buf_h || b.format != fmt)
            .unwrap_or(true);
        if needs_alloc {
            shm_buf = Some(ShmBuffer::new(&shm, &qh, buf_w, buf_h, fmt)?);
        }

        let buf = shm_buf.as_ref().expect("shm buffer initialized");
        state.frame_ready = false;
        state.frame_failed = None;
        state.frame_transform = wl_output::Transform::Normal;

        let frame = session.create_frame(&qh, ());
        frame.attach_buffer(&buf.buffer);
        frame.damage_buffer(0, 0, buf_w as i32, buf_h as i32);
        frame.capture();
        let _ = conn.flush();

        while !state.frame_ready && state.frame_failed.is_none() && !state.session_stopped {
            eq.blocking_dispatch(&mut state)
                .map_err(|e| format!("wayland dispatch error waiting for captured frame: {e}"))?;
        }
        frame.destroy();
        let _ = conn.flush();

        if state.frame_ready {
            let (norm_w, norm_h, norm_bytes) =
                normalize_transform(buf.bytes(), buf_w, buf_h, state.frame_transform);
            let result = match target {
                CaptureTarget::Output { crop: Some(crop), .. } => {
                    let clamped = clamp_rect_in_bounds(*crop, norm_w, norm_h);
                    let cropped = crop_frame_bytes(&norm_bytes, norm_w, clamped);
                    CapturedFrame {
                        width: clamped.w,
                        height: clamped.h,
                        layout: current_layout,
                        data: cropped,
                    }
                }
                _ => CapturedFrame {
                    width: norm_w,
                    height: norm_h,
                    layout: current_layout,
                    data: norm_bytes,
                },
            };
            session.destroy();
            source.destroy();
            let _ = conn.flush();
            return Ok(result);
        }

        if state.session_stopped {
            break;
        }
        match state.frame_failed {
            Some(FailureReason::BufferConstraints) if attempt < 3 => {
                state.session_done = false;
                while !state.session_done && !state.session_stopped {
                    eq.blocking_dispatch(&mut state)
                        .map_err(|e| format!("wayland dispatch error updating constraints: {e}"))?;
                }
            }
            Some(reason) => {
                session.destroy();
                source.destroy();
                return Err(format!("frame capture failed ({reason:?})"));
            }
            None => {}
        }
    }

    session.destroy();
    source.destroy();
    Err("capture session stopped before completing frame".to_string())
}

/// Encodes `frame` as a PNG image, writes it atomically to `path`, and returns the encoded bytes.
pub fn save_frame_as_png(frame: &CapturedFrame, path: &Path) -> Result<Vec<u8>, String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
        }
    }

    let rgb = convert_frame_to_rgb24(&frame.data, frame.layout);
    let mut png_bytes = Vec::with_capacity((frame.width * frame.height * 3) as usize / 2 + 1024);
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, frame.width, frame.height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder
            .write_header()
            .map_err(|e| format!("PNG header encoding error: {e}"))?;
        writer
            .write_image_data(&rgb)
            .map_err(|e| format!("PNG image encoding error: {e}"))?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let write_res = (|| -> std::io::Result<()> {
        {
            let file = fs::File::create(&tmp_path)?;
            let mut bw = BufWriter::new(file);
            std::io::Write::write_all(&mut bw, &png_bytes)?;
            std::io::Write::flush(&mut bw)?;
        }
        fs::rename(&tmp_path, path)
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
        fs::write(path, &png_bytes)
            .map_err(|e| format!("failed to write screenshot {}: {e}", path.display()))?;
    }

    Ok(png_bytes)
}

/// Spawns a background Wayland capture thread pushing frames into a shared buffer until
/// `stop_flag` is set or the capture source stops.
pub fn spawn_stream_capture(
    target: CaptureTarget,
    show_pointer: bool,
    align_even: bool,
    stop_flag: Arc<AtomicBool>,
) -> Result<(StreamMeta, Arc<Mutex<SharedFrame>>, JoinHandle<Result<(), String>>), String> {
    let (meta_tx, meta_rx) = mpsc::sync_channel::<Result<(StreamMeta, Arc<Mutex<SharedFrame>>), String>>(1);

    let handle = thread::Builder::new()
        .name("serenity-cap-wl".to_string())
        .spawn(move || stream_capture_loop(target, show_pointer, align_even, stop_flag, meta_tx))
        .map_err(|e| format!("failed to spawn capture thread: {e}"))?;

    let init = meta_rx
        .recv()
        .map_err(|e| format!("capture thread exited before initializing stream: {e}"))?;
    let (meta, shared) = init?;
    Ok((meta, shared, handle))
}

fn stream_capture_loop(
    target: CaptureTarget,
    show_pointer: bool,
    align_even: bool,
    stop_flag: Arc<AtomicBool>,
    meta_tx: mpsc::SyncSender<Result<(StreamMeta, Arc<Mutex<SharedFrame>>), String>>,
) -> Result<(), String> {
    let setup = (|| -> Result<_, String> {
        let (conn, mut eq, qh, mut state, source) = connect_and_create_source(&target)?;
        let capture_mgr = state
            .capture_mgr
            .clone()
            .ok_or_else(|| "ext_image_copy_capture_manager_v1 missing".to_string())?;
        let shm = state
            .shm
            .clone()
            .ok_or_else(|| "wl_shm missing".to_string())?;
        let opts = if show_pointer {
            CaptureOptions::PaintCursors
        } else {
            CaptureOptions::empty()
        };
        let session = capture_mgr.create_session(&source, opts, &qh, ());
        state.session_done = false;
        state.session_stopped = false;

        while !state.session_done && !state.session_stopped && !stop_flag.load(Ordering::Acquire) {
            poll_dispatch_once(&conn, &mut eq, &mut state, 100)?;
        }
        if state.session_stopped {
            return Err("capture session stopped before buffer negotiation".to_string());
        }
        let (buf_w, buf_h) = state
            .buffer_size
            .ok_or_else(|| "capture session missing buffer_size".to_string())?;
        let (fmt, layout) = choose_shm_format(&state.shm_formats)
            .ok_or_else(|| "no supported 32-bit wl_shm format advertised".to_string())?;

        let (out_w, out_h, crop_rect) = match &target {
            CaptureTarget::Output { crop: Some(r), .. } => {
                let c = clamp_rect_with_alignment(*r, buf_w, buf_h, align_even);
                (c.w, c.h, Some(c))
            }
            _ => {
                let (ew, eh) = align_dimensions(buf_w, buf_h, align_even);
                (ew, eh, None)
            }
        };

        let meta = StreamMeta {
            width: out_w,
            height: out_h,
            layout,
        };
        let shared = Arc::new(Mutex::new(SharedFrame {
            seq: 0,
            data: vec![0u8; (out_w as usize) * (out_h as usize) * 4],
        }));

        Ok((conn, eq, qh, state, source, session, shm, fmt, buf_w, buf_h, crop_rect, meta, shared))
    })();

    let (
        conn,
        mut eq,
        qh,
        mut state,
        source,
        session,
        shm,
        mut fmt,
        mut buf_w,
        mut buf_h,
        crop_rect,
        meta,
        shared,
    ) = match setup {
        Ok(v) => {
            let _ = meta_tx.send(Ok((v.11, Arc::clone(&v.12))));
            v
        }
        Err(e) => {
            let _ = meta_tx.send(Err(e.clone()));
            return Err(e);
        }
    };

    let mut shm_buf = ShmBuffer::new(&shm, &qh, buf_w, buf_h, fmt)?;
    let mut seq = 0u64;

    while !stop_flag.load(Ordering::Acquire) && !state.session_stopped {
        state.frame_ready = false;
        state.frame_failed = None;
        state.frame_transform = wl_output::Transform::Normal;

        let frame = session.create_frame(&qh, ());
        frame.attach_buffer(&shm_buf.buffer);
        frame.damage_buffer(0, 0, buf_w as i32, buf_h as i32);
        frame.capture();
        let _ = conn.flush();

        while !state.frame_ready
            && state.frame_failed.is_none()
            && !state.session_stopped
            && !stop_flag.load(Ordering::Acquire)
        {
            if let Err(e) = poll_dispatch_once(&conn, &mut eq, &mut state, 100) {
                frame.destroy();
                session.destroy();
                source.destroy();
                return Err(e);
            }
        }

        // Destroy frame before creating the next one (`duplicate_frame` rule).
        frame.destroy();
        let _ = conn.flush();

        if stop_flag.load(Ordering::Acquire) || state.session_stopped {
            break;
        }

        if state.frame_ready {
            let (norm_w, norm_h, norm_bytes) = if state.frame_transform == wl_output::Transform::Normal {
                (buf_w, buf_h, shm_buf.bytes())
            } else {
                // Keep transformed bytes in a temporary Vec when compositor rotates buffers.
                let (tw, th, vec) =
                    normalize_transform(shm_buf.bytes(), buf_w, buf_h, state.frame_transform);
                let mut guard = shared.lock().expect("shared frame mutex poisoned");
                seq += 1;
                guard.seq = seq;
                if let Some(crop) = crop_rect {
                    let clamped = clamp_rect_in_bounds(crop, tw, th);
                    let cropped = crop_frame_bytes(&vec, tw, clamped);
                    fit_frame_into_dimensions(
                        &cropped,
                        clamped.w,
                        clamped.h,
                        meta.width,
                        meta.height,
                        &mut guard.data,
                    );
                } else {
                    fit_frame_into_dimensions(&vec, tw, th, meta.width, meta.height, &mut guard.data);
                }
                continue;
            };

            let mut guard = shared.lock().expect("shared frame mutex poisoned");
            seq += 1;
            guard.seq = seq;
            if let Some(crop) = crop_rect {
                copy_cropped_into_target(
                    norm_bytes,
                    norm_w,
                    norm_h,
                    crop,
                    meta.width,
                    meta.height,
                    &mut guard.data,
                );
            } else {
                fit_frame_into_dimensions(
                    norm_bytes,
                    norm_w,
                    norm_h,
                    meta.width,
                    meta.height,
                    &mut guard.data,
                );
            }
        } else if let Some(reason) = state.frame_failed {
            match reason {
                FailureReason::BufferConstraints => {
                    state.session_done = false;
                    while !state.session_done
                        && !state.session_stopped
                        && !stop_flag.load(Ordering::Acquire)
                    {
                        poll_dispatch_once(&conn, &mut eq, &mut state, 100)?;
                    }
                    if let Some((nw, nh)) = state.buffer_size {
                        if let Some((nfmt, _nlayout)) = choose_shm_format(&state.shm_formats) {
                            buf_w = nw;
                            buf_h = nh;
                            fmt = nfmt;
                            shm_buf = ShmBuffer::new(&shm, &qh, buf_w, buf_h, fmt)?;
                        }
                    }
                }
                FailureReason::Stopped => {
                    break;
                }
                FailureReason::Unknown => {
                    // Retry gently on transient errors unless stopped.
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                _ => break,
            }
        }
    }

    session.destroy();
    source.destroy();
    let _ = conn.flush();
    Ok(())
}

type ConnectedSource = (
    Connection,
    EventQueue<WaylandCaptureState>,
    QueueHandle<WaylandCaptureState>,
    WaylandCaptureState,
    ExtImageCaptureSourceV1,
);

fn connect_and_create_source(target: &CaptureTarget) -> Result<ConnectedSource, String> {
    let conn = Connection::connect_to_env()
        .map_err(|e| format!("failed to connect to Wayland display: {e}"))?;
    let mut eq = conn.new_event_queue();
    let qh = eq.handle();
    let mut state = WaylandCaptureState::default();

    let _registry = conn.display().get_registry(&qh, ());
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 1 failed: {e}"))?;
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 2 failed: {e}"))?;

    let source = match target {
        CaptureTarget::Output { output_name, .. } => {
            let out_src_mgr = state.output_source_mgr.clone().ok_or_else(|| {
                "compositor does not expose ext_output_image_capture_source_manager_v1".to_string()
            })?;
            let output_entry = match output_name {
                Some(wanted) => state
                    .outputs
                    .iter()
                    .find(|o| o.name == *wanted)
                    .ok_or_else(|| format!("Wayland output '{wanted}' not found"))?,
                None => state
                    .outputs
                    .first()
                    .ok_or_else(|| "no Wayland outputs available to capture".to_string())?,
            };
            out_src_mgr.create_source(&output_entry.proxy, &qh, ())
        }
        CaptureTarget::Window { identifier } => {
            let win_src_mgr = state.toplevel_source_mgr.clone().ok_or_else(|| {
                "compositor does not expose ext_foreign_toplevel_image_capture_source_manager_v1"
                    .to_string()
            })?;
            let handle = state
                .toplevels
                .iter()
                .find(|t| !t.closed && t.identifier == *identifier)
                .ok_or_else(|| format!("window '{identifier}' is no longer open"))?;
            win_src_mgr.create_source(&handle.proxy, &qh, ())
        }
    };

    Ok((conn, eq, qh, state, source))
}

/// Chooses the best supported 32-bit SHM pixel format and its byte layout.
pub fn choose_shm_format(formats: &[ShmFormat]) -> Option<(ShmFormat, PixelLayout)> {
    for &preferred in &[
        ShmFormat::Xrgb8888,
        ShmFormat::Argb8888,
        ShmFormat::Xbgr8888,
        ShmFormat::Abgr8888,
    ] {
        if formats.contains(&preferred) {
            let layout = match preferred {
                ShmFormat::Xrgb8888 | ShmFormat::Argb8888 => PixelLayout::Bgrx,
                ShmFormat::Xbgr8888 | ShmFormat::Abgr8888 => PixelLayout::Rgbx,
                _ => unreachable!(),
            };
            return Some((preferred, layout));
        }
    }
    None
}

/// Swizzles 4-byte `Bgrx` (`[B,G,R,_]`) or `Rgbx` (`[R,G,B,_]`) pixels into packed RGB24 bytes.
pub fn convert_frame_to_rgb24(data: &[u8], layout: PixelLayout) -> Vec<u8> {
    let mut rgb = Vec::with_capacity((data.len() / 4) * 3);
    match layout {
        PixelLayout::Bgrx => {
            for px in data.chunks_exact(4) {
                rgb.push(px[2]);
                rgb.push(px[1]);
                rgb.push(px[0]);
            }
        }
        PixelLayout::Rgbx => {
            for px in data.chunks_exact(4) {
                rgb.push(px[0]);
                rgb.push(px[1]);
                rgb.push(px[2]);
            }
        }
    }
    rgb
}

fn clamp_rect_in_bounds(rect: Rect, buf_w: u32, buf_h: u32) -> Rect {
    clamp_rect_with_alignment(rect, buf_w, buf_h, false)
}

fn clamp_rect_with_alignment(rect: Rect, buf_w: u32, buf_h: u32, align_even: bool) -> Rect {
    if buf_w == 0 || buf_h == 0 {
        return Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
    }
    let min_dim = if align_even { 2 } else { 1 };
    let mut x = (rect.x.max(0) as u32).min(buf_w.saturating_sub(min_dim));
    let mut y = (rect.y.max(0) as u32).min(buf_h.saturating_sub(min_dim));
    let mut w = rect.w.max(min_dim).min(buf_w - x);
    let mut h = rect.h.max(min_dim).min(buf_h - y);
    if align_even {
        if buf_w >= 2 {
            w = (w & !1).max(2);
            if x + w > buf_w {
                x = buf_w - w;
            }
        }
        if buf_h >= 2 {
            h = (h & !1).max(2);
            if y + h > buf_h {
                y = buf_h - h;
            }
        }
    }
    Rect {
        x: x as i32,
        y: y as i32,
        w,
        h,
    }
}

fn crop_frame_bytes(src: &[u8], src_w: u32, crop: Rect) -> Vec<u8> {
    let mut out = vec![0u8; (crop.w as usize) * (crop.h as usize) * 4];
    let src_stride = (src_w as usize) * 4;
    let dst_stride = (crop.w as usize) * 4;
    let start_x = (crop.x.max(0) as usize) * 4;
    let start_y = crop.y.max(0) as usize;
    for row in 0..(crop.h as usize) {
        let src_off = (start_y + row) * src_stride + start_x;
        let dst_off = row * dst_stride;
        if src_off + dst_stride <= src.len() {
            out[dst_off..dst_off + dst_stride].copy_from_slice(&src[src_off..src_off + dst_stride]);
        }
    }
    out
}

fn copy_cropped_into_target(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    crop: Rect,
    dst_w: u32,
    dst_h: u32,
    dst: &mut [u8],
) {
    dst.fill(0);
    let x0 = crop.x.max(0) as u32;
    let y0 = crop.y.max(0) as u32;
    if x0 >= src_w || y0 >= src_h {
        return;
    }
    let copy_w = crop.w.min(dst_w).min(src_w - x0) as usize;
    let copy_h = crop.h.min(dst_h).min(src_h - y0) as usize;
    let src_stride = (src_w as usize) * 4;
    let dst_stride = (dst_w as usize) * 4;
    let row_bytes = copy_w * 4;
    for row in 0..copy_h {
        let s_off = ((y0 as usize) + row) * src_stride + (x0 as usize) * 4;
        let d_off = row * dst_stride;
        if s_off + row_bytes <= src.len() && d_off + row_bytes <= dst.len() {
            dst[d_off..d_off + row_bytes].copy_from_slice(&src[s_off..s_off + row_bytes]);
        }
    }
}

fn fit_frame_into_dimensions(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    dst_w: u32,
    dst_h: u32,
    dst: &mut [u8],
) {
    if src_w == dst_w && src_h == dst_h && src.len() >= dst.len() {
        dst.copy_from_slice(&src[..dst.len()]);
        return;
    }
    dst.fill(0);
    let copy_w = src_w.min(dst_w) as usize;
    let copy_h = src_h.min(dst_h) as usize;
    let src_stride = (src_w as usize) * 4;
    let dst_stride = (dst_w as usize) * 4;
    let row_bytes = copy_w * 4;
    for row in 0..copy_h {
        let s_off = row * src_stride;
        let d_off = row * dst_stride;
        if s_off + row_bytes <= src.len() && d_off + row_bytes <= dst.len() {
            dst[d_off..d_off + row_bytes].copy_from_slice(&src[s_off..s_off + row_bytes]);
        }
    }
}

fn normalize_transform(
    src: &[u8],
    w: u32,
    h: u32,
    transform: wl_output::Transform,
) -> (u32, u32, Vec<u8>) {
    if transform == wl_output::Transform::Normal {
        return (w, h, src.to_vec());
    }
    let (out_w, out_h) = match transform {
        wl_output::Transform::_90
        | wl_output::Transform::_270
        | wl_output::Transform::Flipped90
        | wl_output::Transform::Flipped270 => (h, w),
        _ => (w, h),
    };
    let mut out = vec![0u8; (out_w as usize) * (out_h as usize) * 4];
    for sy in 0..h {
        for sx in 0..w {
            let (dx, dy) = match transform {
                wl_output::Transform::Normal => (sx, sy),
                wl_output::Transform::_90 => (sy, w - 1 - sx),
                wl_output::Transform::_180 => (w - 1 - sx, h - 1 - sy),
                wl_output::Transform::_270 => (h - 1 - sy, sx),
                wl_output::Transform::Flipped => (w - 1 - sx, sy),
                wl_output::Transform::Flipped90 => (sy, sx),
                wl_output::Transform::Flipped180 => (sx, h - 1 - sy),
                wl_output::Transform::Flipped270 => (h - 1 - sy, w - 1 - sx),
                _ => (sx, sy),
            };
            let s_idx = ((sy * w + sx) * 4) as usize;
            let d_idx = ((dy * out_w + dx) * 4) as usize;
            if s_idx + 4 <= src.len() && d_idx + 4 <= out.len() {
                out[d_idx..d_idx + 4].copy_from_slice(&src[s_idx..s_idx + 4]);
            }
        }
    }
    (out_w, out_h, out)
}

struct RegisteredOutput {
    global_name: u32,
    proxy: WlOutput,
    xdg_output: Option<ZxdgOutputV1>,
    name: String,
    description: String,
    logical_x: i32,
    logical_y: i32,
    logical_w: i32,
    logical_h: i32,
    mode_w: i32,
    mode_h: i32,
    scale: i32,
}

struct RegisteredToplevel {
    proxy: ExtForeignToplevelHandleV1,
    identifier: String,
    title: String,
    app_id: String,
    closed: bool,
}

struct WaylandCaptureState {
    shm: Option<WlShm>,
    capture_mgr: Option<ExtImageCopyCaptureManagerV1>,
    output_source_mgr: Option<ExtOutputImageCaptureSourceManagerV1>,
    toplevel_source_mgr: Option<ExtForeignToplevelImageCaptureSourceManagerV1>,
    toplevel_list: Option<ExtForeignToplevelListV1>,
    xdg_output_mgr: Option<ZxdgOutputManagerV1>,

    outputs: Vec<RegisteredOutput>,
    output_index_by_id: HashMap<ObjectId, usize>,
    output_index_by_global: HashMap<u32, usize>,

    toplevels: Vec<RegisteredToplevel>,
    toplevel_index_by_id: HashMap<ObjectId, usize>,

    buffer_size: Option<(u32, u32)>,
    shm_formats: Vec<ShmFormat>,
    session_done: bool,
    session_stopped: bool,

    frame_transform: wl_output::Transform,
    frame_ready: bool,
    frame_failed: Option<FailureReason>,
}

impl Default for WaylandCaptureState {
    fn default() -> Self {
        Self {
            shm: None,
            capture_mgr: None,
            output_source_mgr: None,
            toplevel_source_mgr: None,
            toplevel_list: None,
            xdg_output_mgr: None,
            outputs: Vec::new(),
            output_index_by_id: HashMap::new(),
            output_index_by_global: HashMap::new(),
            toplevels: Vec::new(),
            toplevel_index_by_id: HashMap::new(),
            buffer_size: None,
            shm_formats: Vec::new(),
            session_done: false,
            session_stopped: false,
            frame_transform: wl_output::Transform::Normal,
            frame_ready: false,
            frame_failed: None,
        }
    }
}

impl Dispatch<WlRegistry, ()> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        registry: &WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match interface.as_str() {
                "wl_shm" => {
                    state.shm = Some(registry.bind::<WlShm, _, _>(name, version.min(2), qh, ()));
                }
                "wl_output" => {
                    let out = registry.bind::<WlOutput, _, _>(name, version.min(4), qh, name);
                    let id = out.id();
                    let idx = state.outputs.len();
                    state.outputs.push(RegisteredOutput {
                        global_name: name,
                        proxy: out,
                        xdg_output: None,
                        name: format!("output-{name}"),
                        description: String::new(),
                        logical_x: 0,
                        logical_y: 0,
                        logical_w: 0,
                        logical_h: 0,
                        mode_w: 0,
                        mode_h: 0,
                        scale: 1,
                    });
                    state.output_index_by_id.insert(id, idx);
                    state.output_index_by_global.insert(name, idx);
                }
                "zxdg_output_manager_v1" => {
                    state.xdg_output_mgr =
                        Some(registry.bind::<ZxdgOutputManagerV1, _, _>(name, version.min(3), qh, ()));
                }
                "ext_image_copy_capture_manager_v1" => {
                    state.capture_mgr = Some(registry.bind::<ExtImageCopyCaptureManagerV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    ));
                }
                "ext_output_image_capture_source_manager_v1" => {
                    state.output_source_mgr =
                        Some(registry.bind::<ExtOutputImageCaptureSourceManagerV1, _, _>(
                            name,
                            version.min(1),
                            qh,
                            (),
                        ));
                }
                "ext_foreign_toplevel_image_capture_source_manager_v1" => {
                    state.toplevel_source_mgr = Some(
                        registry.bind::<ExtForeignToplevelImageCaptureSourceManagerV1, _, _>(
                            name,
                            version.min(1),
                            qh,
                            (),
                        ),
                    );
                }
                "ext_foreign_toplevel_list_v1" => {
                    state.toplevel_list = Some(registry.bind::<ExtForeignToplevelListV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    ));
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<WlShm, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &WlShm,
        _: wayland_client::protocol::wl_shm::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlShmPool, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &WlShmPool,
        _: wayland_client::protocol::wl_shm_pool::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &WlBuffer,
        _: wayland_client::protocol::wl_buffer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlOutput, u32> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        _: &WlOutput,
        event: wl_output::Event,
        global_name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(&idx) = state.output_index_by_global.get(global_name) else {
            return;
        };
        let out = &mut state.outputs[idx];
        match event {
            wl_output::Event::Geometry { x, y, .. } => {
                if out.logical_w == 0 {
                    out.logical_x = x;
                    out.logical_y = y;
                }
            }
            wl_output::Event::Mode {
                flags,
                width,
                height,
                ..
            } => {
                if let WEnum::Value(f) = flags {
                    if f.contains(wl_output::Mode::Current) || out.mode_w == 0 {
                        out.mode_w = width;
                        out.mode_h = height;
                    }
                }
            }
            wl_output::Event::Scale { factor } => {
                out.scale = factor.max(1);
            }
            wl_output::Event::Name { name } => {
                out.name = name;
            }
            wl_output::Event::Description { description } => {
                out.description = description;
            }
            _ => {}
        }
    }
}

impl Dispatch<ZxdgOutputManagerV1, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &ZxdgOutputManagerV1,
        _: wayland_protocols::xdg::xdg_output::zv1::client::zxdg_output_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZxdgOutputV1, u32> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        _: &ZxdgOutputV1,
        event: zxdg_output_v1::Event,
        global_name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(&idx) = state.output_index_by_global.get(global_name) else {
            return;
        };
        let out = &mut state.outputs[idx];
        match event {
            zxdg_output_v1::Event::LogicalPosition { x, y } => {
                out.logical_x = x;
                out.logical_y = y;
            }
            zxdg_output_v1::Event::LogicalSize { width, height } => {
                out.logical_w = width;
                out.logical_h = height;
            }
            zxdg_output_v1::Event::Name { name } => {
                out.name = name;
            }
            zxdg_output_v1::Event::Description { description } => {
                out.description = description;
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtImageCopyCaptureManagerV1, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &ExtImageCopyCaptureManagerV1,
        _: wayland_protocols::ext::image_copy_capture::v1::client::ext_image_copy_capture_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtOutputImageCaptureSourceManagerV1, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &ExtOutputImageCaptureSourceManagerV1,
        _: wayland_protocols::ext::image_capture_source::v1::client::ext_output_image_capture_source_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtForeignToplevelImageCaptureSourceManagerV1, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &ExtForeignToplevelImageCaptureSourceManagerV1,
        _: wayland_protocols::ext::image_capture_source::v1::client::ext_foreign_toplevel_image_capture_source_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtImageCaptureSourceV1, ()> for WaylandCaptureState {
    fn event(
        _: &mut Self,
        _: &ExtImageCaptureSourceV1,
        _: wayland_protocols::ext::image_capture_source::v1::client::ext_image_capture_source_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtImageCopyCaptureSessionV1, ()> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureSessionV1,
        event: ext_image_copy_capture_session_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_image_copy_capture_session_v1::Event::BufferSize { width, height } => {
                state.buffer_size = Some((width, height));
                state.shm_formats.clear();
            }
            ext_image_copy_capture_session_v1::Event::ShmFormat { format } => {
                if let WEnum::Value(fmt) = format {
                    state.shm_formats.push(fmt);
                }
            }
            ext_image_copy_capture_session_v1::Event::Done => {
                state.session_done = true;
            }
            ext_image_copy_capture_session_v1::Event::Stopped => {
                state.session_stopped = true;
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtImageCopyCaptureFrameV1, ()> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureFrameV1,
        event: ext_image_copy_capture_frame_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_image_copy_capture_frame_v1::Event::Transform { transform } => {
                if let WEnum::Value(t) = transform {
                    state.frame_transform = t;
                }
            }
            ext_image_copy_capture_frame_v1::Event::Ready => {
                state.frame_ready = true;
            }
            ext_image_copy_capture_frame_v1::Event::Failed { reason } => {
                state.frame_failed = match reason {
                    WEnum::Value(r) => Some(r),
                    WEnum::Unknown(_) => Some(FailureReason::Unknown),
                };
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtForeignToplevelListV1, ()> for WaylandCaptureState {
    event_created_child!(WaylandCaptureState, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
    ]);

    fn event(
        state: &mut Self,
        _: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            let id = toplevel.id();
            let idx = state.toplevels.len();
            state.toplevels.push(RegisteredToplevel {
                proxy: toplevel,
                identifier: String::new(),
                title: String::new(),
                app_id: String::new(),
                closed: false,
            });
            state.toplevel_index_by_id.insert(id, idx);
        }
    }
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for WaylandCaptureState {
    fn event(
        state: &mut Self,
        handle: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(&idx) = state.toplevel_index_by_id.get(&handle.id()) else {
            return;
        };
        let entry = &mut state.toplevels[idx];
        match event {
            ext_foreign_toplevel_handle_v1::Event::Title { title } => {
                entry.title = title;
            }
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                entry.app_id = app_id;
            }
            ext_foreign_toplevel_handle_v1::Event::Identifier { identifier } => {
                entry.identifier = identifier;
            }
            ext_foreign_toplevel_handle_v1::Event::Closed => {
                entry.closed = true;
            }
            ext_foreign_toplevel_handle_v1::Event::Done => {}
            _ => {}
        }
    }
}
