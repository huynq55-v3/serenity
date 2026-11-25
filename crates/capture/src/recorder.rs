//! Screen recording pipeline: `ext-image-copy-capture-v1` + fixed-FPS pacer + FFmpeg + indicator pill.

use crate::capture::{poll_dispatch_once, spawn_stream_capture, CaptureTarget, SharedFrame};
use crate::font::FontRenderer;
use crate::shm::{blit_pixmap_to_argb8888, ShmBuffer};
use crate::ui::{fill_circle, fill_rounded_rect, stroke_rounded_rect};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tiny_skia::{Color, Pixmap};
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_compositor::WlCompositor;
use wayland_client::protocol::wl_pointer::{self, ButtonState, WlPointer};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_seat::{self, Capability, WlSeat};
use wayland_client::protocol::wl_shm::{Format as ShmFormat, WlShm};
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::protocol::wl_surface::WlSurface;
use wayland_client::{Connection, Dispatch, QueueHandle, WEnum};
use wayland_protocols::wp::cursor_shape::v1::client::{
    wp_cursor_shape_device_v1::{Shape as CursorShape, WpCursorShapeDeviceV1},
    wp_cursor_shape_manager_v1::WpCursorShapeManagerV1,
};
use wayland_protocols_wlr::layer_shell::v1::client::{
    zwlr_layer_shell_v1::{Layer, ZwlrLayerShellV1},
    zwlr_layer_surface_v1::{self, Anchor, KeyboardInteractivity, ZwlrLayerSurfaceV1},
};

const PILL_W: u32 = 176;
const PILL_H: u32 = 36;
const BTN_LEFT_MOUSE: u32 = 272;

/// Configuration for a screen recording session.
#[derive(Debug, Clone)]
pub struct RecordConfig {
    pub target: CaptureTarget,
    pub show_pointer: bool,
    pub audio_system: bool,
    pub audio_mic: bool,
    pub fps: u32,
    pub out_path: PathBuf,
    pub duration_secs: Option<u64>,
    pub show_indicator: bool,
}

/// Summary of a completed screen recording.
#[derive(Debug, Clone)]
pub struct RecordResult {
    pub path: PathBuf,
    pub duration_secs: u64,
    pub bytes: u64,
}

/// Runs the full Wayland -> FFmpeg screen recording pipeline until stopped.
pub fn record_screen(
    config: RecordConfig,
    stop_flag: Arc<AtomicBool>,
) -> Result<RecordResult, String> {
    let fps = config.fps.clamp(5, 120);
    if let Some(parent) = config.out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
        }
    }

    let system_monitor = if config.audio_system {
        discover_system_monitor()
    } else {
        None
    };
    let mic_source = if config.audio_mic {
        discover_mic_source()
    } else {
        None
    };

    let (meta, shared, cap_handle) = spawn_stream_capture(
        config.target.clone(),
        config.show_pointer,
        true,
        Arc::clone(&stop_flag),
    )?;

    // Wait for first frame ready (up to 3s) so FFmpeg does not ingest blank frames.
    let wait_start = Instant::now();
    loop {
        if stop_flag.load(Ordering::Acquire) {
            let _ = cap_handle.join();
            return Err("recording cancelled before first frame arrived".to_string());
        }
        {
            let guard = shared.lock().expect("shared frame mutex poisoned");
            if guard.seq >= 1 {
                break;
            }
        }
        if wait_start.elapsed() > Duration::from_secs(3) {
            stop_flag.store(true, Ordering::Release);
            let _ = cap_handle.join();
            return Err("timed out waiting for first captured frame".to_string());
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut child = spawn_ffmpeg(
        meta.width,
        meta.height,
        meta.layout.ffmpeg_pix_fmt(),
        fps,
        system_monitor.as_deref(),
        mic_source.as_deref(),
        &config.out_path,
    )?;

    let mut ffmpeg_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open FFmpeg stdin pipe".to_string())?;
    let mut ffmpeg_stderr = child.stderr.take();

    let rec_start = Instant::now();
    let pacer_stop = Arc::clone(&stop_flag);
    let pacer_shared = Arc::clone(&shared);
    let max_duration = config.duration_secs;
    let pacer_done = Arc::new(AtomicBool::new(false));
    let pacer_done_flag = Arc::clone(&pacer_done);

    let pacer_handle = thread::Builder::new()
        .name("serenity-rec-pace".to_string())
        .spawn(move || {
            let result = run_pacer_loop(
                &mut ffmpeg_stdin,
                &pacer_shared,
                &pacer_stop,
                fps,
                max_duration,
                rec_start,
            );
            let _ = ffmpeg_stdin.flush();
            drop(ffmpeg_stdin);
            pacer_done_flag.store(true, Ordering::Release);
            result
        })
        .map_err(|e| format!("failed to spawn frame pacer thread: {e}"))?;

    if config.show_indicator {
        if let Err(err) = run_indicator_pill(
            &stop_flag,
            &pacer_done,
            rec_start,
            system_monitor.is_some(),
            mic_source.is_some(),
        ) {
            eprintln!("[serenity-capture] indicator warning: {err}");
            wait_for_stop(&stop_flag, &pacer_done);
        }
    } else {
        wait_for_stop(&stop_flag, &pacer_done);
    }

    stop_flag.store(true, Ordering::Release);

    let pacer_res = pacer_handle
        .join()
        .map_err(|_| "frame pacer thread panicked".to_string())?;

    let status = finalize_ffmpeg(&mut child)?;
    let _ = cap_handle.join();

    let mut stderr_buf = String::new();
    if let Some(mut se) = ffmpeg_stderr.take() {
        let _ = se.read_to_string(&mut stderr_buf);
    }

    pacer_res?;

    if !status.success() {
        return Err(format!(
            "ffmpeg exited with {status}: {}",
            stderr_buf.trim()
        ));
    }

    let file_meta = std::fs::metadata(&config.out_path).map_err(|e| {
        format!(
            "recording output missing at {}: {e}",
            config.out_path.display()
        )
    })?;
    if file_meta.len() == 0 {
        return Err(format!(
            "recording output {} is empty ({})",
            config.out_path.display(),
            stderr_buf.trim()
        ));
    }

    Ok(RecordResult {
        path: config.out_path,
        duration_secs: rec_start.elapsed().as_secs().max(1),
        bytes: file_meta.len(),
    })
}

fn wait_for_stop(stop_flag: &AtomicBool, pacer_done: &AtomicBool) {
    while !stop_flag.load(Ordering::Acquire) && !pacer_done.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_pacer_loop(
    stdin: &mut impl Write,
    shared: &Arc<Mutex<SharedFrame>>,
    stop_flag: &AtomicBool,
    fps: u32,
    duration_secs: Option<u64>,
    start: Instant,
) -> Result<(), String> {
    let frame_ns = 1_000_000_000u64 / (fps as u64);
    let mut local_buf = Vec::new();
    let mut frame_idx = 0u64;

    loop {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }
        if let Some(dur) = duration_secs {
            if start.elapsed() >= Duration::from_secs(dur) {
                stop_flag.store(true, Ordering::Release);
                break;
            }
        }

        {
            let guard = shared.lock().expect("shared frame mutex poisoned");
            if local_buf.len() != guard.data.len() {
                local_buf.resize(guard.data.len(), 0);
            }
            local_buf.copy_from_slice(&guard.data);
        }

        if let Err(e) = stdin.write_all(&local_buf) {
            if stop_flag.load(Ordering::Acquire) {
                break;
            }
            stop_flag.store(true, Ordering::Release);
            return Err(format!("failed writing video frame to ffmpeg: {e}"));
        }

        frame_idx += 1;
        let next_tick = start + Duration::from_nanos(frame_idx * frame_ns);
        let now = Instant::now();
        if next_tick > now {
            thread::sleep(next_tick - now);
        }
    }

    Ok(())
}

fn spawn_ffmpeg(
    width: u32,
    height: u32,
    pix_fmt: &str,
    fps: u32,
    system_monitor: Option<&str>,
    mic_source: Option<&str>,
    out_path: &Path,
) -> Result<Child, String> {
    let ffmpeg_bin = if Path::new("/usr/bin/ffmpeg").exists() {
        "/usr/bin/ffmpeg"
    } else {
        "ffmpeg"
    };

    let mut cmd = Command::new(ffmpeg_bin);
    cmd.args(["-hide_banner", "-loglevel", "warning", "-y"]);
    cmd.args([
        "-f",
        "rawvideo",
        "-pixel_format",
        pix_fmt,
        "-video_size",
        &format!("{width}x{height}"),
        "-framerate",
        &fps.to_string(),
        "-i",
        "pipe:0",
    ]);

    let mut audio_inputs = 0usize;
    if let Some(mon) = system_monitor {
        cmd.args(["-thread_queue_size", "1024", "-f", "pulse", "-i", mon]);
        audio_inputs += 1;
    }
    if let Some(mic) = mic_source {
        cmd.args(["-thread_queue_size", "1024", "-f", "pulse", "-i", mic]);
        audio_inputs += 1;
    }

    match audio_inputs {
        2 => {
            cmd.args([
                "-filter_complex",
                "[1:a][2:a]amix=inputs=2:duration=longest:normalize=0[aout]",
                "-map",
                "0:v",
                "-map",
                "[aout]",
            ]);
        }
        1 => {
            cmd.args(["-map", "0:v", "-map", "1:a"]);
        }
        _ => {
            cmd.args(["-map", "0:v"]);
        }
    }

    cmd.args([
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-crf",
        "23",
        "-pix_fmt",
        "yuv420p",
    ]);

    if audio_inputs > 0 {
        cmd.args(["-c:a", "aac", "-b:a", "192k"]);
    }

    cmd.args(["-shortest", "-movflags", "+faststart"]);
    cmd.arg(out_path);

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    cmd.spawn()
        .map_err(|e| format!("failed to launch {ffmpeg_bin}: {e}"))
}

fn finalize_ffmpeg(child: &mut Child) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("failed polling ffmpeg exit: {e}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Ask FFmpeg politely via SIGINT to flush the MP4 moov atom.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    let sigint_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("failed polling ffmpeg exit after SIGINT: {e}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= sigint_deadline {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    child
        .wait()
        .map_err(|e| format!("failed waiting for ffmpeg termination: {e}"))
}

fn pulse_socket_available() -> bool {
    if std::env::var_os("PULSE_SERVER").is_some() {
        return true;
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        return Path::new(&rt).join("pulse/native").exists();
    }
    false
}

fn discover_system_monitor() -> Option<String> {
    if !pulse_socket_available() {
        eprintln!("[serenity-capture] PulseAudio socket unavailable; recording without system audio");
        return None;
    }
    let wpctl = if Path::new("/usr/bin/wpctl").exists() {
        "/usr/bin/wpctl"
    } else {
        "wpctl"
    };
    let out = match Command::new(wpctl)
        .args(["inspect", "@DEFAULT_AUDIO_SINK@"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[serenity-capture] wpctl unavailable ({e}); recording without system audio");
            return None;
        }
    };
    if !out.status.success() {
        eprintln!("[serenity-capture] no default audio sink; recording without system audio");
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("node.name") {
            if let Some((_, val)) = trimmed.split_once('=') {
                let name = val.trim().trim_matches('"');
                if !name.is_empty() {
                    return Some(format!("{name}.monitor"));
                }
            }
        }
    }
    eprintln!("[serenity-capture] default audio sink missing node.name; skipping system audio");
    None
}

fn discover_mic_source() -> Option<String> {
    if !pulse_socket_available() {
        eprintln!("[serenity-capture] PulseAudio socket unavailable; recording without microphone");
        return None;
    }
    let wpctl = if Path::new("/usr/bin/wpctl").exists() {
        "/usr/bin/wpctl"
    } else {
        "wpctl"
    };
    let out = match Command::new(wpctl)
        .args(["inspect", "@DEFAULT_AUDIO_SOURCE@"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[serenity-capture] wpctl unavailable ({e}); recording without microphone");
            return None;
        }
    };
    if !out.status.success() {
        eprintln!("[serenity-capture] no default microphone source; skipping microphone");
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("node.name") {
        Some("default".to_string())
    } else {
        None
    }
}

fn run_indicator_pill(
    stop_flag: &AtomicBool,
    pacer_done: &AtomicBool,
    rec_start: Instant,
    has_audio: bool,
    has_mic: bool,
) -> Result<(), String> {
    let conn = Connection::connect_to_env()
        .map_err(|e| format!("failed to connect to Wayland for indicator: {e}"))?;
    let mut eq = conn.new_event_queue();
    let qh = eq.handle();

    let mut state = IndicatorState::new(has_audio, has_mic);
    let _registry = conn.display().get_registry(&qh, ());
    eq.roundtrip(&mut state)
        .map_err(|e| format!("indicator roundtrip 1 failed: {e}"))?;
    eq.roundtrip(&mut state)
        .map_err(|e| format!("indicator roundtrip 2 failed: {e}"))?;

    let compositor = state
        .compositor
        .clone()
        .ok_or_else(|| "wl_compositor unavailable".to_string())?;
    let layer_shell = state
        .layer_shell
        .clone()
        .ok_or_else(|| "zwlr_layer_shell_v1 unavailable".to_string())?;
    let shm = state
        .shm
        .clone()
        .ok_or_else(|| "wl_shm unavailable".to_string())?;

    let surface = compositor.create_surface(&qh, ());
    let layer_surface = layer_shell.get_layer_surface(
        &surface,
        None,
        Layer::Overlay,
        "serenity-capture-indicator".to_string(),
        &qh,
        (),
    );
    layer_surface.set_size(PILL_W, PILL_H);
    layer_surface.set_anchor(Anchor::Top | Anchor::Right);
    layer_surface.set_margin(10, 16, 0, 0);
    layer_surface.set_exclusive_zone(0);
    layer_surface.set_keyboard_interactivity(KeyboardInteractivity::None);
    surface.commit();
    let _ = conn.flush();

    state.surface = Some(surface);
    state.layer_surface = Some(layer_surface);

    while !state.configured
        && !state.closed
        && !stop_flag.load(Ordering::Acquire)
        && !pacer_done.load(Ordering::Acquire)
    {
        poll_dispatch_once(&conn, &mut eq, &mut state, 100)?;
    }

    let mut shm_buf = ShmBuffer::new(&shm, &qh, PILL_W, PILL_H, ShmFormat::Argb8888)?;
    let mut pixmap = Pixmap::new(PILL_W, PILL_H).ok_or("failed to allocate indicator pixmap")?;
    let mut last_draw = Instant::now() - Duration::from_secs(1);

    while !state.clicked_stop
        && !state.closed
        && !stop_flag.load(Ordering::Acquire)
        && !pacer_done.load(Ordering::Acquire)
    {
        if last_draw.elapsed() >= Duration::from_millis(500) {
            state.render_pill(&mut pixmap, rec_start.elapsed());
            blit_pixmap_to_argb8888(&pixmap, shm_buf.bytes_mut());
            if let Some(surf) = &state.surface {
                surf.attach(Some(&shm_buf.buffer), 0, 0);
                surf.damage_buffer(0, 0, PILL_W as i32, PILL_H as i32);
                surf.commit();
                let _ = conn.flush();
            }
            last_draw = Instant::now();
        }

        poll_dispatch_once(&conn, &mut eq, &mut state, 250)?;
        if state.clicked_stop {
            stop_flag.store(true, Ordering::Release);
            break;
        }
    }

    if let Some(ls) = state.layer_surface.take() {
        ls.destroy();
    }
    if let Some(surf) = state.surface.take() {
        surf.destroy();
    }
    if let Some(dev) = state.cursor_device.take() {
        dev.destroy();
    }
    let _ = conn.flush();
    Ok(())
}

struct IndicatorState {
    compositor: Option<WlCompositor>,
    layer_shell: Option<ZwlrLayerShellV1>,
    shm: Option<WlShm>,
    seat: Option<WlSeat>,
    pointer: Option<WlPointer>,
    cursor_shape_mgr: Option<WpCursorShapeManagerV1>,
    cursor_device: Option<WpCursorShapeDeviceV1>,
    surface: Option<WlSurface>,
    layer_surface: Option<ZwlrLayerSurfaceV1>,

    configured: bool,
    closed: bool,
    clicked_stop: bool,
    hovered: bool,
    has_audio: bool,
    has_mic: bool,
    font: FontRenderer,
}

impl IndicatorState {
    fn new(has_audio: bool, has_mic: bool) -> Self {
        Self {
            compositor: None,
            layer_shell: None,
            shm: None,
            seat: None,
            pointer: None,
            cursor_shape_mgr: None,
            cursor_device: None,
            surface: None,
            layer_surface: None,
            configured: false,
            closed: false,
            clicked_stop: false,
            hovered: false,
            has_audio,
            has_mic,
            font: FontRenderer::load(),
        }
    }

    fn render_pill(&self, pm: &mut Pixmap, elapsed: Duration) {
        pm.fill(Color::TRANSPARENT);
        let w = PILL_W as f32;
        let h = PILL_H as f32;

        let bg = if self.hovered {
            Color::from_rgba8(44, 24, 28, 242)
        } else {
            Color::from_rgba8(28, 28, 34, 236)
        };
        fill_rounded_rect(pm, 1.0, 1.0, w - 2.0, h - 2.0, 17.0, bg);
        stroke_rounded_rect(
            pm,
            1.0,
            1.0,
            w - 2.0,
            h - 2.0,
            17.0,
            1.2,
            Color::from_rgba8(224, 27, 36, 195),
        );

        // Blinking live recording dot (on for 500ms, dim for 500ms).
        let blink_on = (elapsed.as_millis() / 500) % 2 == 0;
        let dot_color = if blink_on {
            Color::from_rgba8(239, 41, 41, 255)
        } else {
            Color::from_rgba8(140, 28, 32, 200)
        };
        fill_circle(pm, 18.0, h * 0.5, 5.0, dot_color);

        let secs = elapsed.as_secs();
        let timer = format!("{:02}:{:02}", secs / 60, secs % 60);
        self.font
            .draw_text(pm, 30.0, 10.5, 13.5, Color::WHITE, &timer);

        // Tiny audio/mic badge.
        if self.has_audio || self.has_mic {
            let badge_col = if self.has_mic {
                Color::from_rgba8(255, 170, 64, 240)
            } else {
                Color::from_rgba8(100, 210, 140, 240)
            };
            fill_circle(pm, 82.0, h * 0.5, 3.0, badge_col);
        }

        // Stop button pill on the right.
        let stop_bg = if self.hovered {
            Color::from_rgba8(224, 27, 36, 255)
        } else {
            Color::from_rgba8(224, 27, 36, 220)
        };
        fill_rounded_rect(pm, 96.0, 6.0, 72.0, 24.0, 12.0, stop_bg);
        fill_rounded_rect(pm, 107.0, 13.5, 9.0, 9.0, 1.5, Color::WHITE);
        self.font
            .draw_text(pm, 121.0, 10.5, 12.5, Color::WHITE, "Stop");
    }
}

impl Dispatch<WlRegistry, ()> for IndicatorState {
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
                "wl_compositor" => {
                    state.compositor =
                        Some(registry.bind::<WlCompositor, _, _>(name, version.min(5), qh, ()));
                }
                "zwlr_layer_shell_v1" => {
                    state.layer_shell =
                        Some(registry.bind::<ZwlrLayerShellV1, _, _>(name, version.min(4), qh, ()));
                }
                "wl_shm" => {
                    state.shm = Some(registry.bind::<WlShm, _, _>(name, version.min(2), qh, ()));
                }
                "wl_seat" => {
                    if state.seat.is_none() {
                        state.seat = Some(registry.bind::<WlSeat, _, _>(name, version.min(7), qh, ()));
                    }
                }
                "wp_cursor_shape_manager_v1" => {
                    state.cursor_shape_mgr = Some(
                        registry.bind::<WpCursorShapeManagerV1, _, _>(name, version.min(1), qh, ()),
                    );
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<WlCompositor, ()> for IndicatorState {
    fn event(
        _: &mut Self,
        _: &WlCompositor,
        _: wayland_client::protocol::wl_compositor::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSurface, ()> for IndicatorState {
    fn event(
        _: &mut Self,
        _: &WlSurface,
        _: wayland_client::protocol::wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrLayerShellV1, ()> for IndicatorState {
    fn event(
        _: &mut Self,
        _: &ZwlrLayerShellV1,
        _: wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_shell_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrLayerSurfaceV1, ()> for IndicatorState {
    fn event(
        state: &mut Self,
        ls: &ZwlrLayerSurfaceV1,
        event: zwlr_layer_surface_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_layer_surface_v1::Event::Configure { serial, .. } => {
                ls.ack_configure(serial);
                state.configured = true;
            }
            zwlr_layer_surface_v1::Event::Closed => {
                state.closed = true;
            }
            _ => {}
        }
    }
}

impl Dispatch<WlShm, ()> for IndicatorState {
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

impl Dispatch<WlShmPool, ()> for IndicatorState {
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

impl Dispatch<WlBuffer, ()> for IndicatorState {
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

impl Dispatch<WlSeat, ()> for IndicatorState {
    fn event(
        state: &mut Self,
        seat: &WlSeat,
        event: wl_seat::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities { capabilities } = event {
            if let WEnum::Value(caps) = capabilities {
                if caps.contains(Capability::Pointer) && state.pointer.is_none() {
                    let ptr = seat.get_pointer(qh, ());
                    if let Some(mgr) = &state.cursor_shape_mgr {
                        state.cursor_device = Some(mgr.get_pointer(&ptr, qh, ()));
                    }
                    state.pointer = Some(ptr);
                }
            }
        }
    }
}

impl Dispatch<WlPointer, ()> for IndicatorState {
    fn event(
        state: &mut Self,
        _: &WlPointer,
        event: wl_pointer::Event,
        _: &(),
        conn: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter { serial, .. } => {
                state.hovered = true;
                if let Some(dev) = &state.cursor_device {
                    dev.set_shape(serial, CursorShape::Pointer);
                    let _ = conn.flush();
                }
            }
            wl_pointer::Event::Leave { .. } => {
                state.hovered = false;
            }
            wl_pointer::Event::Button {
                button,
                state: btn_state,
                ..
            } => {
                if button == BTN_LEFT_MOUSE {
                    if let WEnum::Value(ButtonState::Pressed) = btn_state {
                        state.clicked_stop = true;
                    }
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<WpCursorShapeManagerV1, ()> for IndicatorState {
    fn event(
        _: &mut Self,
        _: &WpCursorShapeManagerV1,
        _: wayland_protocols::wp::cursor_shape::v1::client::wp_cursor_shape_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WpCursorShapeDeviceV1, ()> for IndicatorState {
    fn event(
        _: &mut Self,
        _: &WpCursorShapeDeviceV1,
        _: wayland_protocols::wp::cursor_shape::v1::client::wp_cursor_shape_device_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
