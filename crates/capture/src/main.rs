//! `serenity-capture`: Ubuntu-style Print Screen screenshot & screen recorder for Serenity Linux.

mod capture;
mod font;
mod notify;
mod recorder;
mod shm;
mod ui;

use crate::capture::{
    capture_single_frame, discover_environment, map_logical_rect_to_buffer, save_frame_as_png,
    CaptureTarget,
};
use crate::notify::{
    copy_png_to_clipboard, default_recording_path, default_screenshot_path, send_notification,
};
use crate::recorder::{record_screen, RecordConfig};
use crate::ui::{run_overlay, CaptureAction, CaptureKind, OverlayConfig, OverlayResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");

static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandMode {
    Interactive {
        action: CaptureAction,
        kind: CaptureKind,
    },
    FullScreenshot,
    RecordFull,
    Stop,
    Status,
    Help,
    Version,
}

#[derive(Debug, Clone)]
struct CliArgs {
    mode: CommandMode,
    output: Option<PathBuf>,
    duration_secs: Option<u64>,
    fps: u32,
    audio_system: bool,
    audio_mic: bool,
    show_pointer: Option<bool>,
    clipboard: bool,
    notify: bool,
    indicator: bool,
}

fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let prog = args
        .first()
        .and_then(|s| Path::new(s).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("serenity-capture");

    let default_action = if prog == "screen-recorder" {
        CaptureAction::Record
    } else {
        CaptureAction::Screenshot
    };

    let mut parsed = CliArgs {
        mode: CommandMode::Interactive {
            action: default_action,
            kind: CaptureKind::Selection,
        },
        output: None,
        duration_secs: None,
        fps: 30,
        audio_system: true,
        audio_mic: false,
        show_pointer: None,
        clipboard: true,
        notify: true,
        indicator: true,
    };

    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                parsed.mode = CommandMode::Help;
                return Ok(parsed);
            }
            "-V" | "--version" => {
                parsed.mode = CommandMode::Version;
                return Ok(parsed);
            }
            "-f" | "--full" | "--interactive=false" => {
                parsed.mode = CommandMode::FullScreenshot;
            }
            "-r" | "--region" | "--area" | "--interactive=true" => {
                parsed.mode = CommandMode::Interactive {
                    action: CaptureAction::Screenshot,
                    kind: CaptureKind::Selection,
                };
            }
            "-R" | "--record" => {
                parsed.mode = CommandMode::Interactive {
                    action: CaptureAction::Record,
                    kind: CaptureKind::Selection,
                };
            }
            "--record-full" => {
                parsed.mode = CommandMode::RecordFull;
            }
            "--stop" => {
                parsed.mode = CommandMode::Stop;
            }
            "--status" => {
                parsed.mode = CommandMode::Status;
            }
            "-o" | "--output" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| format!("missing path after {arg}"))?;
                parsed.output = Some(PathBuf::from(val));
            }
            "--duration" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing seconds after --duration".to_string())?;
                let secs: u64 = val
                    .parse()
                    .map_err(|_| format!("invalid --duration value '{val}'"))?;
                if secs == 0 {
                    return Err("--duration must be >= 1".to_string());
                }
                parsed.duration_secs = Some(secs);
            }
            "--fps" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "missing FPS after --fps".to_string())?;
                let fps: u32 = val
                    .parse()
                    .map_err(|_| format!("invalid --fps value '{val}'"))?;
                parsed.fps = fps.clamp(5, 120);
            }
            "--no-audio" => {
                parsed.audio_system = false;
            }
            "--mic" => {
                parsed.audio_mic = true;
            }
            "--pointer" => {
                parsed.show_pointer = Some(true);
            }
            "--no-pointer" => {
                parsed.show_pointer = Some(false);
            }
            "--no-clipboard" => {
                parsed.clipboard = false;
            }
            "--no-notify" => {
                parsed.notify = false;
            }
            "--no-indicator" => {
                parsed.indicator = false;
            }
            other => {
                return Err(format!("unknown argument '{other}' (try --help)"));
            }
        }
        i += 1;
    }

    Ok(parsed)
}

fn print_help() {
    println!("serenity-capture {VERSION} — Ubuntu-style Screenshot & Screen Recorder");
    println!();
    println!("Usage:");
    println!("  serenity-capture                      Open Ubuntu-style Print Screen HUD (or stop active recording)");
    println!("  serenity-capture --record, -R         Open HUD pre-selected in Screen Record mode");
    println!("  serenity-capture --region, -r         Open HUD in Screenshot Selection mode");
    println!("  serenity-capture --full, -f           Capture full screen immediately to PNG + clipboard");
    println!("  serenity-capture --record-full        Record full screen immediately to MP4");
    println!("  serenity-capture --stop               Stop an active recording cleanly");
    println!("  serenity-capture --status             Print active capture/recording status");
    println!();
    println!("Options:");
    println!("  -o, --output <path>                   Custom output PNG or MP4 path");
    println!("      --duration <secs>                 Stop --record-full automatically after N seconds");
    println!("      --fps <30|60>                     Framerate for recording (default: 30)");
    println!("      --no-audio                        Disable system audio recording");
    println!("      --mic                             Include default microphone input");
    println!("      --pointer / --no-pointer          Include or hide pointer cursor");
    println!("      --no-clipboard                    Skip wl-copy clipboard update");
    println!("      --no-notify                       Skip desktop notification");
    println!("      --no-indicator                    Hide floating Stop pill during recording");
    println!("  -V, --version                         Show version");
    println!("  -h, --help                            Show this help");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PidState {
    pid: u32,
    mode: String,
    start_epoch: u64,
    output_path: String,
}

fn pid_file_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/tmp".to_string());
    PathBuf::from(dir).join("serenity-capture.pid")
}

fn parse_pid_state(raw: &str) -> Option<PidState> {
    let mut lines = raw.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let mode = lines.next().unwrap_or("unknown").trim().to_string();
    let start_epoch: u64 = lines.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let output_path = lines.next().unwrap_or("").trim().to_string();
    Some(PidState {
        pid,
        mode,
        start_epoch,
        output_path,
    })
}

fn is_capture_process_alive(pid: u32) -> bool {
    let comm_path = format!("/proc/{pid}/comm");
    let Ok(comm) = fs::read_to_string(&comm_path) else {
        return false;
    };
    let name = comm.trim();
    name.starts_with("serenity-captur") || name == "screen-recorder"
}

fn read_active_pid_state() -> Option<PidState> {
    let path = pid_file_path();
    let content = fs::read_to_string(&path).ok()?;
    let state = parse_pid_state(&content)?;
    if state.pid == std::process::id() || !is_capture_process_alive(state.pid) {
        let _ = fs::remove_file(&path);
        return None;
    }
    Some(state)
}

fn write_pid_state(mode: &str, output_path: &Path) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let content = format!(
        "{}\n{}\n{}\n{}\n",
        std::process::id(),
        mode,
        now,
        output_path.display()
    );
    let _ = fs::write(pid_file_path(), content);
}

struct PidGuard {
    active: bool,
}

impl PidGuard {
    fn acquire(mode: &str, output_path: &Path) -> Self {
        write_pid_state(mode, output_path);
        Self { active: true }
    }

    fn update(&self, mode: &str, output_path: &Path) {
        if self.active {
            write_pid_state(mode, output_path);
        }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(pid_file_path());
        }
    }
}

fn stop_active_instance(state: &PidState) -> Result<(), String> {
    unsafe {
        if libc::kill(state.pid as libc::pid_t, libc::SIGTERM) != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("failed to signal pid {}: {err}", state.pid));
        }
    }
    for _ in 0..100 {
        if !is_capture_process_alive(state.pid) {
            let _ = fs::remove_file(pid_file_path());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for pid {} to finalize", state.pid))
}

fn make_stop_arc() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let bridge = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("serenity-sig-watch".to_string())
        .spawn(move || {
            while !bridge.load(Ordering::Relaxed) {
                if SIGNAL_STOP.load(Ordering::Relaxed) {
                    bridge.store(true, Ordering::Release);
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        })
        .ok();
    stop
}

fn run_screenshot(
    target: CaptureTarget,
    show_pointer: bool,
    out_path: PathBuf,
    clipboard: bool,
    notify_user: bool,
) -> Result<(), String> {
    let frame = capture_single_frame(&target, show_pointer)?;
    let png_bytes = save_frame_as_png(&frame, &out_path)?;
    if clipboard {
        if let Err(e) = copy_png_to_clipboard(&png_bytes) {
            eprintln!("[serenity-capture] clipboard warning: {e}");
        }
    }
    println!("Saved screenshot: {}", out_path.display());
    if notify_user {
        let body = if clipboard {
            format!("Saved to {} and copied to clipboard.", out_path.display())
        } else {
            format!("Saved to {}", out_path.display())
        };
        send_notification("Screenshot Captured", &body, "serenity-capture");
    }
    Ok(())
}

fn resolve_buffer_crop(
    sel: crate::capture::Rect,
    surf_w: u32,
    surf_h: u32,
    output_name: Option<&str>,
    align_even: bool,
) -> crate::capture::Rect {
    if let Ok((outputs, _)) = discover_environment() {
        let chosen = output_name
            .and_then(|n| outputs.iter().find(|o| o.name == n))
            .or_else(|| outputs.first());
        if let Some(out) = chosen {
            let buf_w = out.mode_w.max(surf_w as i32) as u32;
            let buf_h = out.mode_h.max(surf_h as i32) as u32;
            return map_logical_rect_to_buffer(sel, surf_w, surf_h, buf_w, buf_h, align_even);
        }
    }
    map_logical_rect_to_buffer(sel, surf_w, surf_h, surf_w, surf_h, align_even)
}

fn run() -> Result<(), String> {
    install_signal_handlers();
    let argv: Vec<String> = std::env::args().collect();
    let cli = parse_args(&argv)?;

    match cli.mode {
        CommandMode::Help => {
            print_help();
            return Ok(());
        }
        CommandMode::Version => {
            println!("serenity-capture {VERSION}");
            return Ok(());
        }
        CommandMode::Status => {
            if let Some(active) = read_active_pid_state() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let elapsed = now.saturating_sub(active.start_epoch);
                println!(
                    "{} (pid={}, elapsed={}s, output={})",
                    active.mode, active.pid, elapsed, active.output_path
                );
            } else {
                println!("idle");
            }
            return Ok(());
        }
        CommandMode::Stop => {
            if let Some(active) = read_active_pid_state() {
                stop_active_instance(&active)?;
                println!("Stopped active {} (pid {})", active.mode, active.pid);
            } else {
                println!("No active capture or recording.");
            }
            return Ok(());
        }
        CommandMode::FullScreenshot => {
            let out_path = cli.output.unwrap_or_else(default_screenshot_path);
            let show_pointer = cli.show_pointer.unwrap_or(false);
            return run_screenshot(
                CaptureTarget::Output {
                    output_name: None,
                    crop: None,
                },
                show_pointer,
                out_path,
                cli.clipboard,
                cli.notify,
            );
        }
        CommandMode::RecordFull => {
            if let Some(active) = read_active_pid_state() {
                return Err(format!(
                    "another capture instance is already active ({}, pid {})",
                    active.mode, active.pid
                ));
            }
            let out_path = cli.output.unwrap_or_else(default_recording_path);
            let pid_guard = PidGuard::acquire("recording", &out_path);
            let stop = make_stop_arc();
            let result = record_screen(
                RecordConfig {
                    target: CaptureTarget::Output {
                        output_name: None,
                        crop: None,
                    },
                    show_pointer: cli.show_pointer.unwrap_or(true),
                    audio_system: cli.audio_system,
                    audio_mic: cli.audio_mic,
                    fps: cli.fps,
                    out_path,
                    duration_secs: cli.duration_secs,
                    show_indicator: cli.indicator,
                },
                Arc::clone(&stop),
            )?;
            stop.store(true, Ordering::Release);
            drop(pid_guard);
            println!(
                "Saved screencast: {} ({}s, {} KiB)",
                result.path.display(),
                result.duration_secs,
                result.bytes / 1024
            );
            if cli.notify {
                send_notification(
                    "Screencast Saved",
                    &format!("Saved to {}", result.path.display()),
                    "serenity-recorder",
                );
            }
            return Ok(());
        }
        CommandMode::Interactive { action, kind } => {
            if let Some(active) = read_active_pid_state() {
                stop_active_instance(&active)?;
                println!("Stopped active {} (pid {})", active.mode, active.pid);
                return Ok(());
            }

            let pid_guard = PidGuard::acquire("overlay", Path::new(""));
            let stop = make_stop_arc();
            let overlay_res = run_overlay(
                OverlayConfig {
                    action,
                    kind,
                    show_pointer: cli
                        .show_pointer
                        .unwrap_or(action == CaptureAction::Record),
                    audio_system: cli.audio_system,
                    audio_mic: cli.audio_mic,
                    fps: cli.fps,
                },
                &stop,
            )?;

            match overlay_res {
                OverlayResult::Cancelled => {
                    stop.store(true, Ordering::Release);
                    drop(pid_guard);
                    return Ok(());
                }
                OverlayResult::Confirmed {
                    action,
                    target_kind,
                    output_name,
                    selection_logical,
                    surf_w,
                    surf_h,
                    window_id,
                    show_pointer,
                    audio_system,
                    audio_mic,
                    fps,
                } => {
                    let is_record = action == CaptureAction::Record;
                    let target = match target_kind {
                        CaptureKind::Screen => CaptureTarget::Output {
                            output_name,
                            crop: None,
                        },
                        CaptureKind::Selection => {
                            let crop = selection_logical.map(|sel| {
                                resolve_buffer_crop(
                                    sel,
                                    surf_w,
                                    surf_h,
                                    output_name.as_deref(),
                                    is_record,
                                )
                            });
                            CaptureTarget::Output { output_name, crop }
                        }
                        CaptureKind::Window => {
                            let identifier = window_id.ok_or_else(|| {
                                "no window selected (open a window or pick Selection/Screen)"
                                    .to_string()
                            })?;
                            CaptureTarget::Window { identifier }
                        }
                    };

                    if is_record {
                        let out_path = cli.output.unwrap_or_else(default_recording_path);
                        pid_guard.update("recording", &out_path);
                        let result = record_screen(
                            RecordConfig {
                                target,
                                show_pointer,
                                audio_system,
                                audio_mic,
                                fps,
                                out_path,
                                duration_secs: cli.duration_secs,
                                show_indicator: cli.indicator,
                            },
                            Arc::clone(&stop),
                        )?;
                        stop.store(true, Ordering::Release);
                        drop(pid_guard);
                        println!(
                            "Saved screencast: {} ({}s, {} KiB)",
                            result.path.display(),
                            result.duration_secs,
                            result.bytes / 1024
                        );
                        if cli.notify {
                            send_notification(
                                "Screencast Saved",
                                &format!("Saved to {}", result.path.display()),
                                "serenity-recorder",
                            );
                        }
                    } else {
                        stop.store(true, Ordering::Release);
                        drop(pid_guard);
                        let out_path = cli.output.unwrap_or_else(default_screenshot_path);
                        run_screenshot(target, show_pointer, out_path, cli.clipboard, cli.notify)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[serenity-capture] ERROR: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{convert_frame_to_rgb24, PixelLayout, Rect};
    use crate::shm::blit_pixmap_to_argb8888;
    use crate::ui::{HudButton, HudLayout};
    use tiny_skia::{Color, Pixmap};

    #[test]
    fn test_map_logical_rect_to_buffer() {
        // HiDPI 2x scaling with even alignment for H.264.
        let r = map_logical_rect_to_buffer(
            Rect {
                x: 100,
                y: 50,
                w: 301,
                h: 199,
            },
            1920,
            1080,
            3840,
            2160,
            true,
        );
        assert_eq!(r.x, 200);
        assert_eq!(r.y, 100);
        assert_eq!(r.w % 2, 0);
        assert_eq!(r.h % 2, 0);
        assert_eq!(r.w, 602);
        assert_eq!(r.h, 398);

        // Odd width without align_even stays exact.
        let r2 = map_logical_rect_to_buffer(
            Rect {
                x: 10,
                y: 20,
                w: 101,
                h: 55,
            },
            1920,
            1080,
            1920,
            1080,
            false,
        );
        assert_eq!(
            r2,
            Rect {
                x: 10,
                y: 20,
                w: 101,
                h: 55
            }
        );

        // Clamping near right/bottom edge with even enforcement.
        let r3 = map_logical_rect_to_buffer(
            Rect {
                x: 1900,
                y: 1070,
                w: 100,
                h: 100,
            },
            1920,
            1080,
            1920,
            1080,
            true,
        );
        assert!(r3.x as u32 + r3.w <= 1920);
        assert!(r3.y as u32 + r3.h <= 1080);
        assert_eq!(r3.w % 2, 0);
        assert_eq!(r3.h % 2, 0);
        assert!(r3.w >= 2 && r3.h >= 2);
    }

    #[test]
    fn test_pixel_swizzle_and_rgb24() {
        let mut pm = Pixmap::new(2, 1).unwrap();
        pm.fill(Color::from_rgba8(0x11, 0x22, 0x33, 0xFF));
        let mut argb = vec![0u8; 8];
        blit_pixmap_to_argb8888(&pm, &mut argb);
        assert_eq!(&argb[0..4], &[0x33, 0x22, 0x11, 0xFF]);

        let rgb_from_bgrx = convert_frame_to_rgb24(&[0x33, 0x22, 0x11, 0xFF], PixelLayout::Bgrx);
        assert_eq!(rgb_from_bgrx, vec![0x11, 0x22, 0x33]);

        let rgb_from_rgbx = convert_frame_to_rgb24(&[0x11, 0x22, 0x33, 0xFF], PixelLayout::Rgbx);
        assert_eq!(rgb_from_rgbx, vec![0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_cli_parsing() {
        let default_shot = parse_args(&["serenity-capture".to_string()]).unwrap();
        assert_eq!(
            default_shot.mode,
            CommandMode::Interactive {
                action: CaptureAction::Screenshot,
                kind: CaptureKind::Selection,
            }
        );

        let symlink_rec = parse_args(&["/usr/bin/screen-recorder".to_string()]).unwrap();
        assert_eq!(
            symlink_rec.mode,
            CommandMode::Interactive {
                action: CaptureAction::Record,
                kind: CaptureKind::Selection,
            }
        );

        let rec_full = parse_args(&[
            "serenity-capture".into(),
            "--record-full".into(),
            "--duration".into(),
            "5".into(),
            "--fps".into(),
            "60".into(),
            "--mic".into(),
            "--no-audio".into(),
            "--no-indicator".into(),
            "--output".into(),
            "/tmp/out.mp4".into(),
        ])
        .unwrap();
        assert_eq!(rec_full.mode, CommandMode::RecordFull);
        assert_eq!(rec_full.duration_secs, Some(5));
        assert_eq!(rec_full.fps, 60);
        assert!(!rec_full.audio_system);
        assert!(rec_full.audio_mic);
        assert!(!rec_full.indicator);
        assert_eq!(rec_full.output, Some(PathBuf::from("/tmp/out.mp4")));
    }

    #[test]
    fn test_pid_file_parsing_and_hud_hit_testing() {
        let parsed = parse_pid_state("12345\nrecording\n1700000000\n/tmp/test.mp4\n").unwrap();
        assert_eq!(
            parsed,
            PidState {
                pid: 12345,
                mode: "recording".to_string(),
                start_epoch: 1700000000,
                output_path: "/tmp/test.mp4".to_string(),
            }
        );

        let hud = HudLayout::compute(1920.0, 1080.0);
        let center_of = |r: crate::ui::UiRect| (r.x + r.w * 0.5, r.y + r.h * 0.5);

        let (sx, sy) = center_of(hud.shutter);
        assert_eq!(
            hud.hit_test(sx, sy, CaptureAction::Screenshot),
            Some(HudButton::Shutter)
        );

        let (ax, ay) = center_of(hud.toggle_audio);
        assert_eq!(
            hud.hit_test(ax, ay, CaptureAction::Record),
            Some(HudButton::ToggleAudio)
        );
        assert_eq!(hud.hit_test(ax, ay, CaptureAction::Screenshot), None);

        let (cx, cy) = center_of(hud.close);
        assert_eq!(
            hud.hit_test(cx, cy, CaptureAction::Record),
            Some(HudButton::Close)
        );
    }
}
