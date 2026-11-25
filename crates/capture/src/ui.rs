//! Ubuntu GNOME Print Screen interactive overlay (`zwlr_layer_shell_v1` + `tiny-skia`).

use crate::capture::{
    capture_single_frame, discover_environment, poll_dispatch_once, CaptureTarget,
    CapturedFrame, OutputInfo, PixelLayout, Rect, ToplevelInfo,
};
use crate::font::FontRenderer;
use crate::shm::{blit_pixmap_to_argb8888, ShmBuffer};
use std::sync::atomic::{AtomicBool, Ordering};
use tiny_skia::{
    Color, FillRule, LineCap, Paint, PathBuilder, Pixmap, PixmapPaint, Rect as SkRect, Stroke,
    Transform,
};
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_compositor::WlCompositor;
use wayland_client::protocol::wl_keyboard::{self, KeyState, WlKeyboard};
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

const HUD_W: f32 = 540.0;
const HUD_H: f32 = 124.0;
const HUD_BOTTOM_MARGIN: f32 = 36.0;
const BTN_LEFT_MOUSE: u32 = 272; // Linux BTN_LEFT

/// Primary capture action selected in the HUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureAction {
    Screenshot,
    Record,
}

/// Capture region target mode selected in the HUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    Selection,
    Screen,
    Window,
}

/// Initial state when launching the interactive overlay.
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub action: CaptureAction,
    pub kind: CaptureKind,
    pub show_pointer: bool,
    pub audio_system: bool,
    pub audio_mic: bool,
    pub fps: u32,
}

/// User outcome from the interactive overlay.
#[derive(Debug, Clone)]
pub enum OverlayResult {
    Cancelled,
    Confirmed {
        action: CaptureAction,
        target_kind: CaptureKind,
        output_name: Option<String>,
        selection_logical: Option<Rect>,
        surf_w: u32,
        surf_h: u32,
        window_id: Option<String>,
        show_pointer: bool,
        audio_system: bool,
        audio_mic: bool,
        fps: u32,
    },
}

/// Rectangular UI widget bounds used for rendering and hit-testing.
#[derive(Debug, Clone, Copy)]
pub struct UiRect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl UiRect {
    pub fn contains(self, px: f32, py: f32) -> bool {
        px >= self.x && px <= self.x + self.w && py >= self.y && py <= self.y + self.h
    }
}

/// Interactive elements inside the floating HUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HudButton {
    TargetSelection,
    TargetScreen,
    TargetWindow,
    TogglePointer,
    Close,
    ModeScreenshot,
    ModeRecord,
    Shutter,
    ToggleAudio,
    ToggleMic,
    ToggleFps,
}

/// Computed layout geometry of the bottom floating pill HUD.
#[derive(Debug, Clone, Copy)]
pub struct HudLayout {
    pub panel: UiRect,
    pub target_selection: UiRect,
    pub target_screen: UiRect,
    pub target_window: UiRect,
    pub toggle_pointer: UiRect,
    pub close: UiRect,
    pub mode_screenshot: UiRect,
    pub mode_record: UiRect,
    pub shutter: UiRect,
    pub toggle_audio: UiRect,
    pub toggle_mic: UiRect,
    pub toggle_fps: UiRect,
}

impl HudLayout {
    /// Computes deterministic HUD button coordinates for a surface of size `(surf_w, surf_h)`.
    pub fn compute(surf_w: f32, surf_h: f32) -> Self {
        let px = ((surf_w - HUD_W) * 0.5).max(8.0);
        let py = (surf_h - HUD_H - HUD_BOTTOM_MARGIN).max(8.0);

        let top_y = py + 14.0;
        let top_h = 34.0;
        let bot_y = py + 70.0;

        Self {
            panel: UiRect {
                x: px,
                y: py,
                w: HUD_W,
                h: HUD_H,
            },
            target_selection: UiRect {
                x: px + 18.0,
                y: top_y,
                w: 104.0,
                h: top_h,
            },
            target_screen: UiRect {
                x: px + 126.0,
                y: top_y,
                w: 96.0,
                h: top_h,
            },
            target_window: UiRect {
                x: px + 226.0,
                y: top_y,
                w: 102.0,
                h: top_h,
            },
            toggle_pointer: UiRect {
                x: px + 344.0,
                y: top_y,
                w: 126.0,
                h: top_h,
            },
            close: UiRect {
                x: px + 488.0,
                y: top_y + 1.0,
                w: 32.0,
                h: 32.0,
            },
            mode_screenshot: UiRect {
                x: px + 18.0,
                y: py + 66.0,
                w: 66.0,
                h: 40.0,
            },
            mode_record: UiRect {
                x: px + 88.0,
                y: py + 66.0,
                w: 66.0,
                h: 40.0,
            },
            shutter: UiRect {
                x: px + 246.0,
                y: py + 62.0,
                w: 48.0,
                h: 48.0,
            },
            toggle_audio: UiRect {
                x: px + 322.0,
                y: bot_y,
                w: 66.0,
                h: 32.0,
            },
            toggle_mic: UiRect {
                x: px + 394.0,
                y: bot_y,
                w: 56.0,
                h: 32.0,
            },
            toggle_fps: UiRect {
                x: px + 456.0,
                y: bot_y,
                w: 66.0,
                h: 32.0,
            },
        }
    }

    /// Returns which HUD button contains `(x, y)`, if any.
    pub fn hit_test(&self, x: f32, y: f32, action: CaptureAction) -> Option<HudButton> {
        if !self.panel.contains(x, y) {
            return None;
        }
        if self.target_selection.contains(x, y) {
            return Some(HudButton::TargetSelection);
        }
        if self.target_screen.contains(x, y) {
            return Some(HudButton::TargetScreen);
        }
        if self.target_window.contains(x, y) {
            return Some(HudButton::TargetWindow);
        }
        if self.toggle_pointer.contains(x, y) {
            return Some(HudButton::TogglePointer);
        }
        if self.close.contains(x, y) {
            return Some(HudButton::Close);
        }
        if self.mode_screenshot.contains(x, y) {
            return Some(HudButton::ModeScreenshot);
        }
        if self.mode_record.contains(x, y) {
            return Some(HudButton::ModeRecord);
        }
        if self.shutter.contains(x, y) {
            return Some(HudButton::Shutter);
        }
        if action == CaptureAction::Record {
            if self.toggle_audio.contains(x, y) {
                return Some(HudButton::ToggleAudio);
            }
            if self.toggle_mic.contains(x, y) {
                return Some(HudButton::ToggleMic);
            }
            if self.toggle_fps.contains(x, y) {
                return Some(HudButton::ToggleFps);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Nw,
    N,
    Ne,
    E,
    Se,
    S,
    Sw,
    W,
}

#[derive(Debug, Clone, Copy)]
enum DragState {
    None,
    MoveSelection {
        start_x: f32,
        start_y: f32,
        orig: Rect,
    },
    NewSelection {
        anchor_x: f32,
        anchor_y: f32,
    },
    ResizeSelection {
        handle: HandleKind,
        orig: Rect,
    },
}

/// Runs the interactive Print Screen HUD and returns the user's capture choice.
pub fn run_overlay(config: OverlayConfig, stop_flag: &AtomicBool) -> Result<OverlayResult, String> {
    let (outputs, toplevels) = discover_environment()?;
    let frozen_frame = capture_single_frame(
        &CaptureTarget::Output {
            output_name: outputs.first().map(|o| o.name.clone()),
            crop: None,
        },
        false,
    )
    .ok();

    let conn = Connection::connect_to_env()
        .map_err(|e| format!("failed to connect to Wayland display: {e}"))?;
    let mut eq = conn.new_event_queue();
    let qh = eq.handle();

    let mut state = OverlayState::new(config, outputs, toplevels, frozen_frame);
    let _registry = conn.display().get_registry(&qh, ());
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 1 failed: {e}"))?;
    eq.roundtrip(&mut state)
        .map_err(|e| format!("wayland roundtrip 2 failed: {e}"))?;

    let compositor = state
        .compositor
        .clone()
        .ok_or_else(|| "compositor does not expose wl_compositor".to_string())?;
    let layer_shell = state
        .layer_shell
        .clone()
        .ok_or_else(|| "compositor does not expose zwlr_layer_shell_v1".to_string())?;
    let shm = state
        .shm
        .clone()
        .ok_or_else(|| "compositor does not expose wl_shm".to_string())?;

    let surface = compositor.create_surface(&qh, ());
    let layer_surface = layer_shell.get_layer_surface(
        &surface,
        None,
        Layer::Overlay,
        "serenity-capture-overlay".to_string(),
        &qh,
        (),
    );
    layer_surface.set_anchor(Anchor::Top | Anchor::Bottom | Anchor::Left | Anchor::Right);
    layer_surface.set_exclusive_zone(-1);
    layer_surface.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
    surface.commit();
    let _ = conn.flush();

    state.surface = Some(surface);
    state.layer_surface = Some(layer_surface);

    while !state.configured && !state.closed && !stop_flag.load(Ordering::Acquire) {
        poll_dispatch_once(&conn, &mut eq, &mut state, 50)?;
    }
    if state.closed || stop_flag.load(Ordering::Acquire) {
        state.destroy_surfaces(&conn);
        return Ok(OverlayResult::Cancelled);
    }

    let mut shm_buf: Option<ShmBuffer> = None;
    let mut pixmap: Option<Pixmap> = None;

    state.needs_redraw = true;

    while !state.finished && !state.closed && !stop_flag.load(Ordering::Acquire) {
        if state.needs_redraw && state.surf_w > 0 && state.surf_h > 0 {
            let w = state.surf_w;
            let h = state.surf_h;
            let realloc = shm_buf
                .as_ref()
                .map(|b| b.width != w || b.height != h)
                .unwrap_or(true);
            if realloc {
                shm_buf = Some(ShmBuffer::new(&shm, &qh, w, h, ShmFormat::Argb8888)?);
                pixmap = Pixmap::new(w, h);
                state.ensure_scaled_frozen(w, h);
                state.init_default_selection();
            }

            if let (Some(buf), Some(pm), Some(surf)) =
                (shm_buf.as_mut(), pixmap.as_mut(), state.surface.as_ref())
            {
                state.render(pm);
                blit_pixmap_to_argb8888(pm, buf.bytes_mut());
                surf.attach(Some(&buf.buffer), 0, 0);
                surf.damage_buffer(0, 0, w as i32, h as i32);
                surf.commit();
                let _ = conn.flush();
            }
            state.needs_redraw = false;
        }

        poll_dispatch_once(&conn, &mut eq, &mut state, 50)?;
        state.update_cursor_shape(&conn);
    }

    let confirmed = state.confirmed && !stop_flag.load(Ordering::Acquire) && !state.closed;
    let result = if confirmed {
        state.build_confirmed_result()
    } else {
        OverlayResult::Cancelled
    };

    state.destroy_surfaces(&conn);
    let _ = eq.roundtrip(&mut state);
    if confirmed {
        std::thread::sleep(std::time::Duration::from_millis(45));
    }

    Ok(result)
}

struct OverlayState {
    compositor: Option<WlCompositor>,
    layer_shell: Option<ZwlrLayerShellV1>,
    shm: Option<WlShm>,
    seat: Option<WlSeat>,
    pointer: Option<WlPointer>,
    keyboard: Option<WlKeyboard>,
    cursor_shape_mgr: Option<WpCursorShapeManagerV1>,
    cursor_device: Option<WpCursorShapeDeviceV1>,

    surface: Option<WlSurface>,
    layer_surface: Option<ZwlrLayerSurfaceV1>,

    configured: bool,
    closed: bool,
    finished: bool,
    confirmed: bool,
    needs_redraw: bool,

    surf_w: u32,
    surf_h: u32,

    action: CaptureAction,
    kind: CaptureKind,
    show_pointer: bool,
    audio_system: bool,
    audio_mic: bool,
    fps: u32,

    outputs: Vec<OutputInfo>,
    selected_output_idx: usize,
    toplevels: Vec<ToplevelInfo>,
    selected_window_idx: usize,

    selection: Rect,
    drag: DragState,
    pointer_x: f32,
    pointer_y: f32,
    pointer_enter_serial: u32,
    last_cursor: CursorShape,
    hovered_button: Option<HudButton>,

    frozen_raw: Option<CapturedFrame>,
    frozen_pixmap: Option<Pixmap>,
    font: FontRenderer,
}

impl OverlayState {
    fn new(
        config: OverlayConfig,
        outputs: Vec<OutputInfo>,
        toplevels: Vec<ToplevelInfo>,
        frozen_raw: Option<CapturedFrame>,
    ) -> Self {
        Self {
            compositor: None,
            layer_shell: None,
            shm: None,
            seat: None,
            pointer: None,
            keyboard: None,
            cursor_shape_mgr: None,
            cursor_device: None,
            surface: None,
            layer_surface: None,
            configured: false,
            closed: false,
            finished: false,
            confirmed: false,
            needs_redraw: false,
            surf_w: 0,
            surf_h: 0,
            action: config.action,
            kind: config.kind,
            show_pointer: config.show_pointer,
            audio_system: config.audio_system,
            audio_mic: config.audio_mic,
            fps: if config.fps == 60 { 60 } else { 30 },
            outputs,
            selected_output_idx: 0,
            toplevels,
            selected_window_idx: 0,
            selection: Rect {
                x: 200,
                y: 120,
                w: 800,
                h: 500,
            },
            drag: DragState::None,
            pointer_x: -1.0,
            pointer_y: -1.0,
            pointer_enter_serial: 0,
            last_cursor: CursorShape::Default,
            hovered_button: None,
            frozen_raw,
            frozen_pixmap: None,
            font: FontRenderer::load(),
        }
    }

    fn destroy_surfaces(&mut self, conn: &Connection) {
        if let Some(ls) = self.layer_surface.take() {
            ls.destroy();
        }
        if let Some(surf) = self.surface.take() {
            surf.destroy();
        }
        if let Some(dev) = self.cursor_device.take() {
            dev.destroy();
        }
        let _ = conn.flush();
    }

    fn init_default_selection(&mut self) {
        let sw = self.surf_w as i32;
        let sh = self.surf_h as i32;
        let w = ((sw as f32) * 0.60).round().max(120.0) as u32;
        let h = ((sh as f32) * 0.60).round().max(90.0) as u32;
        let x = ((sw - w as i32) / 2).max(0);
        let y = ((sh - h as i32) / 2).max(0);
        self.selection = Rect { x, y, w, h };
    }

    fn ensure_scaled_frozen(&mut self, surf_w: u32, surf_h: u32) {
        let Some(raw) = &self.frozen_raw else {
            return;
        };
        let Some(mut src_pm) = frame_to_pixmap(raw) else {
            return;
        };
        if raw.width == surf_w && raw.height == surf_h {
            self.frozen_pixmap = Some(src_pm);
            return;
        }
        if let Some(mut dst) = Pixmap::new(surf_w, surf_h) {
            let sx = surf_w as f32 / raw.width as f32;
            let sy = surf_h as f32 / raw.height as f32;
            dst.draw_pixmap(
                0,
                0,
                src_pm.as_ref(),
                &PixmapPaint::default(),
                Transform::from_scale(sx, sy),
                None,
            );
            let _ = &mut src_pm;
            self.frozen_pixmap = Some(dst);
        }
    }

    fn build_confirmed_result(&self) -> OverlayResult {
        let output_name = self
            .outputs
            .get(self.selected_output_idx)
            .map(|o| o.name.clone());
        let selection_logical = if self.kind == CaptureKind::Selection {
            Some(self.selection)
        } else {
            None
        };
        let window_id = if self.kind == CaptureKind::Window {
            self.toplevels
                .get(self.selected_window_idx)
                .map(|t| t.identifier.clone())
        } else {
            None
        };
        OverlayResult::Confirmed {
            action: self.action,
            target_kind: self.kind,
            output_name,
            selection_logical,
            surf_w: self.surf_w,
            surf_h: self.surf_h,
            window_id,
            show_pointer: self.show_pointer,
            audio_system: self.audio_system,
            audio_mic: self.audio_mic,
            fps: self.fps,
        }
    }

    fn render(&self, pm: &mut Pixmap) {
        let w = pm.width() as f32;
        let h = pm.height() as f32;
        pm.fill(Color::TRANSPARENT);

        // Background: Screenshot mode displays frozen desktop capture; Record mode keeps live screen transparent.
        if self.action == CaptureAction::Screenshot {
            if let Some(bg) = &self.frozen_pixmap {
                pm.draw_pixmap(0, 0, bg.as_ref(), &PixmapPaint::default(), Transform::identity(), None);
            }
        }

        let scrim = if self.action == CaptureAction::Screenshot {
            Color::from_rgba8(0, 0, 0, 132)
        } else {
            Color::from_rgba8(0, 0, 0, 114)
        };

        let accent = if self.action == CaptureAction::Record {
            Color::from_rgba8(224, 27, 36, 255)
        } else {
            Color::from_rgba8(53, 132, 228, 255)
        };

        match self.kind {
            CaptureKind::Selection => {
                let r = self.selection;
                let rx = r.x as f32;
                let ry = r.y as f32;
                let rw = r.w as f32;
                let rh = r.h as f32;

                // Dim the 4 surrounding bands without painting over the interior.
                fill_rect(pm, 0.0, 0.0, w, ry, scrim);
                fill_rect(pm, 0.0, ry + rh, w, (h - (ry + rh)).max(0.0), scrim);
                fill_rect(pm, 0.0, ry, rx, rh, scrim);
                fill_rect(pm, rx + rw, ry, (w - (rx + rw)).max(0.0), rh, scrim);

                // Crisp selection outline + subtle dashed/inner guide.
                stroke_rect(pm, rx, ry, rw, rh, 2.0, Color::WHITE);
                if rw > 6.0 && rh > 6.0 {
                    stroke_rect(
                        pm,
                        rx + 1.5,
                        ry + 1.5,
                        rw - 3.0,
                        rh - 3.0,
                        1.0,
                        Color::from_rgba8(0, 0, 0, 96),
                    );
                }

                // 8 circular resize handles.
                for (_, hx, hy) in selection_handles(r) {
                    fill_circle(pm, hx, hy, 6.5, Color::from_rgba8(24, 26, 32, 220));
                    fill_circle(pm, hx, hy, 5.0, Color::WHITE);
                    fill_circle(pm, hx, hy, 2.2, accent);
                }

                // Live W x H badge.
                let label = format!("{} × {}", r.w, r.h);
                let (tw, _) = self.font.measure_text(&label, 12.5);
                let bw = tw + 18.0;
                let bh = 24.0;
                let bx = rx.clamp(8.0, (w - bw - 8.0).max(8.0));
                let by = if ry >= bh + 12.0 {
                    ry - bh - 8.0
                } else {
                    (ry + 8.0).min(h - bh - 8.0)
                };
                fill_rounded_rect(pm, bx, by, bw, bh, 8.0, Color::from_rgba8(24, 26, 32, 228));
                stroke_rounded_rect(pm, bx, by, bw, bh, 8.0, 1.0, Color::from_rgba8(255, 255, 255, 45));
                self.font
                    .draw_centered(pm, bx, by, bw, bh, 12.5, Color::WHITE, &label);
            }
            CaptureKind::Screen => {
                // Full-screen frame border.
                stroke_rounded_rect(pm, 3.0, 3.0, w - 6.0, h - 6.0, 4.0, 4.0, accent);

                if self.outputs.len() > 1 {
                    self.render_output_pills(pm, w, h, accent);
                }
            }
            CaptureKind::Window => {
                let win_scrim = Color::from_rgba8(0, 0, 0, 108);
                fill_rect(pm, 0.0, 0.0, w, h, win_scrim);
                self.render_window_picker(pm, w, h, accent);
            }
        }

        self.render_hud(pm, w, h, accent);
    }

    fn render_output_pills(&self, pm: &mut Pixmap, w: f32, h: f32, accent: Color) {
        let hud = HudLayout::compute(w, h);
        let pill_h = 30.0;
        let gap = 10.0;
        let pill_w = 154.0;
        let total_w = self.outputs.len() as f32 * pill_w + (self.outputs.len() - 1) as f32 * gap;
        let start_x = ((w - total_w) * 0.5).max(12.0);
        let py = (hud.panel.y - pill_h - 14.0).max(12.0);

        for (i, out) in self.outputs.iter().enumerate() {
            let px = start_x + i as f32 * (pill_w + gap);
            let active = i == self.selected_output_idx;
            let bg = if active {
                accent
            } else {
                Color::from_rgba8(34, 36, 42, 235)
            };
            fill_rounded_rect(pm, px, py, pill_w, pill_h, 15.0, bg);
            stroke_rounded_rect(
                pm,
                px,
                py,
                pill_w,
                pill_h,
                15.0,
                1.0,
                Color::from_rgba8(255, 255, 255, 42),
            );
            let label = format!("{} ({}×{})", out.name, out.logical_w, out.logical_h);
            let short = self.font.ellipsize(&label, 12.0, pill_w - 16.0);
            self.font
                .draw_centered(pm, px, py, pill_w, pill_h, 12.0, Color::WHITE, &short);
        }
    }

    fn render_window_picker(&self, pm: &mut Pixmap, w: f32, h: f32, accent: Color) {
        let card = self.window_picker_rect(w, h);
        // Subtle drop shadow.
        fill_rounded_rect(
            pm,
            card.x + 2.0,
            card.y + 6.0,
            card.w,
            card.h,
            20.0,
            Color::from_rgba8(0, 0, 0, 110),
        );
        fill_rounded_rect(
            pm,
            card.x,
            card.y,
            card.w,
            card.h,
            18.0,
            Color::from_rgba8(34, 36, 42, 244),
        );
        stroke_rounded_rect(
            pm,
            card.x,
            card.y,
            card.w,
            card.h,
            18.0,
            1.2,
            Color::from_rgba8(255, 255, 255, 42),
        );

        let title = if self.action == CaptureAction::Record {
            "Select Window to Record"
        } else {
            "Select Window to Capture"
        };
        self.font
            .draw_text(pm, card.x + 22.0, card.y + 18.0, 15.0, Color::WHITE, title);

        if self.toplevels.is_empty() {
            self.font.draw_centered(
                pm,
                card.x,
                card.y + 52.0,
                card.w,
                card.h - 60.0,
                13.5,
                Color::from_rgba8(185, 190, 200, 255),
                "No open windows detected. Choose Selection or Screen.",
            );
            return;
        }

        let max_rows = self.toplevels.len().min(6);
        for i in 0..max_rows {
            let win = &self.toplevels[i];
            let row = UiRect {
                x: card.x + 16.0,
                y: card.y + 52.0 + i as f32 * 48.0,
                w: card.w - 32.0,
                h: 42.0,
            };
            let selected = i == self.selected_window_idx;
            let hovered = row.contains(self.pointer_x, self.pointer_y);
            let bg = if selected {
                accent
            } else if hovered {
                Color::from_rgba8(255, 255, 255, 26)
            } else {
                Color::from_rgba8(255, 255, 255, 12)
            };
            fill_rounded_rect(pm, row.x, row.y, row.w, row.h, 11.0, bg);
            let title_text = self.font.ellipsize(&win.title, 13.5, row.w - 150.0);
            self.font
                .draw_text(pm, row.x + 14.0, row.y + 13.0, 13.5, Color::WHITE, &title_text);

            if !win.app_id.is_empty() {
                let app_short = self.font.ellipsize(&win.app_id, 11.5, 120.0);
                let (aw, _) = self.font.measure_text(&app_short, 11.5);
                let mut app_color = Color::from_rgba8(205, 212, 224, 220);
                if selected {
                    app_color = Color::from_rgba8(255, 255, 255, 235);
                }
                self.font.draw_text(
                    pm,
                    row.x + row.w - aw - 14.0,
                    row.y + 14.0,
                    11.5,
                    app_color,
                    &app_short,
                );
            }
        }
    }

    fn window_picker_rect(&self, w: f32, h: f32) -> UiRect {
        let rows = self.toplevels.len().clamp(1, 6);
        let card_w = 540.0_f32.min(w - 24.0);
        let card_h = (66.0 + rows as f32 * 48.0).min(h - HUD_H - HUD_BOTTOM_MARGIN - 40.0);
        let hud = HudLayout::compute(w, h);
        let card_x = (w - card_w) * 0.5;
        let card_y = ((hud.panel.y - card_h) * 0.5).max(20.0);
        UiRect {
            x: card_x,
            y: card_y,
            w: card_w,
            h: card_h,
        }
    }

    fn render_hud(&self, pm: &mut Pixmap, w: f32, h: f32, accent: Color) {
        let hud = HudLayout::compute(w, h);

        // Soft drop shadow behind floating Ubuntu pill HUD.
        fill_rounded_rect(
            pm,
            hud.panel.x,
            hud.panel.y + 6.0,
            hud.panel.w,
            hud.panel.h,
            24.0,
            Color::from_rgba8(0, 0, 0, 120),
        );
        fill_rounded_rect(
            pm,
            hud.panel.x,
            hud.panel.y,
            hud.panel.w,
            hud.panel.h,
            22.0,
            Color::from_rgba8(34, 36, 42, 242),
        );
        stroke_rounded_rect(
            pm,
            hud.panel.x,
            hud.panel.y,
            hud.panel.w,
            hud.panel.h,
            22.0,
            1.0,
            Color::from_rgba8(255, 255, 255, 38),
        );

        // Segmented target group background.
        fill_rounded_rect(
            pm,
            hud.target_selection.x - 3.0,
            hud.target_selection.y - 2.0,
            318.0,
            38.0,
            14.0,
            Color::from_rgba8(255, 255, 255, 14),
        );

        self.draw_pill_button(
            pm,
            hud.target_selection,
            self.kind == CaptureKind::Selection,
            self.hovered_button == Some(HudButton::TargetSelection),
            Color::from_rgba8(255, 255, 255, 42),
            "Selection",
            Some(IconKind::Selection),
        );
        self.draw_pill_button(
            pm,
            hud.target_screen,
            self.kind == CaptureKind::Screen,
            self.hovered_button == Some(HudButton::TargetScreen),
            Color::from_rgba8(255, 255, 255, 42),
            "Screen",
            Some(IconKind::Screen),
        );
        self.draw_pill_button(
            pm,
            hud.target_window,
            self.kind == CaptureKind::Window,
            self.hovered_button == Some(HudButton::TargetWindow),
            Color::from_rgba8(255, 255, 255, 42),
            "Window",
            Some(IconKind::Window),
        );

        // Pointer toggle pill.
        self.draw_pill_button(
            pm,
            hud.toggle_pointer,
            self.show_pointer,
            self.hovered_button == Some(HudButton::TogglePointer),
            accent,
            "Show Pointer",
            Some(IconKind::Pointer),
        );

        // Close button (X).
        let close_bg = if self.hovered_button == Some(HudButton::Close) {
            Color::from_rgba8(255, 255, 255, 46)
        } else {
            Color::from_rgba8(255, 255, 255, 20)
        };
        let ccx = hud.close.x + hud.close.w * 0.5;
        let ccy = hud.close.y + hud.close.h * 0.5;
        fill_circle(pm, ccx, ccy, 15.0, close_bg);
        draw_line(pm, ccx - 4.5, ccy - 4.5, ccx + 4.5, ccy + 4.5, 1.8, Color::WHITE);
        draw_line(pm, ccx + 4.5, ccy - 4.5, ccx - 4.5, ccy + 4.5, 1.8, Color::WHITE);

        // Bottom-left Screenshot / Record mode switch pill.
        fill_rounded_rect(
            pm,
            hud.mode_screenshot.x - 3.0,
            hud.mode_screenshot.y - 2.0,
            142.0,
            44.0,
            16.0,
            Color::from_rgba8(255, 255, 255, 14),
        );
        self.draw_mode_button(
            pm,
            hud.mode_screenshot,
            self.action == CaptureAction::Screenshot,
            self.hovered_button == Some(HudButton::ModeScreenshot),
            Color::from_rgba8(53, 132, 228, 255),
            IconKind::Camera,
        );
        self.draw_mode_button(
            pm,
            hud.mode_record,
            self.action == CaptureAction::Record,
            self.hovered_button == Some(HudButton::ModeRecord),
            Color::from_rgba8(224, 27, 36, 255),
            IconKind::Video,
        );

        // Center big circular shutter button.
        let scx = hud.shutter.x + hud.shutter.w * 0.5;
        let scy = hud.shutter.y + hud.shutter.h * 0.5;
        let shutter_hover = self.hovered_button == Some(HudButton::Shutter);
        stroke_circle(pm, scx, scy, 23.0, 2.5, Color::WHITE);
        let inner_r = if shutter_hover { 18.0 } else { 16.5 };
        let inner_col = if self.action == CaptureAction::Record {
            Color::from_rgba8(224, 27, 36, 255)
        } else {
            Color::WHITE
        };
        fill_circle(pm, scx, scy, inner_r, inner_col);

        // Bottom-right controls.
        if self.action == CaptureAction::Record {
            self.draw_pill_button(
                pm,
                hud.toggle_audio,
                self.audio_system,
                self.hovered_button == Some(HudButton::ToggleAudio),
                Color::from_rgba8(224, 27, 36, 225),
                "Audio",
                None,
            );
            self.draw_pill_button(
                pm,
                hud.toggle_mic,
                self.audio_mic,
                self.hovered_button == Some(HudButton::ToggleMic),
                Color::from_rgba8(224, 27, 36, 225),
                "Mic",
                None,
            );
            let fps_label = if self.fps == 60 { "60fps" } else { "30fps" };
            self.draw_pill_button(
                pm,
                hud.toggle_fps,
                self.fps == 60,
                self.hovered_button == Some(HudButton::ToggleFps),
                Color::from_rgba8(255, 255, 255, 42),
                fps_label,
                None,
            );
        } else {
            self.font.draw_centered(
                pm,
                hud.panel.x + 318.0,
                hud.panel.y + 70.0,
                206.0,
                32.0,
                12.0,
                Color::from_rgba8(195, 200, 210, 220),
                "Enter: Capture  •  Esc: Cancel",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_pill_button(
        &self,
        pm: &mut Pixmap,
        rect: UiRect,
        active: bool,
        hovered: bool,
        active_color: Color,
        label: &str,
        icon: Option<IconKind>,
    ) {
        let bg = if active {
            active_color
        } else if hovered {
            Color::from_rgba8(255, 255, 255, 26)
        } else {
            Color::from_rgba8(255, 255, 255, 10)
        };
        fill_rounded_rect(pm, rect.x, rect.y, rect.w, rect.h, 11.0, bg);
        let text_color = if active || hovered {
            Color::WHITE
        } else {
            Color::from_rgba8(218, 222, 230, 240)
        };

        if let Some(ic) = icon {
            let icon_cx = rect.x + 16.0;
            let icon_cy = rect.y + rect.h * 0.5;
            draw_vector_icon(pm, ic, icon_cx, icon_cy, text_color);
            self.font.draw_centered(
                pm,
                rect.x + 24.0,
                rect.y,
                rect.w - 28.0,
                rect.h,
                12.0,
                text_color,
                label,
            );
        } else {
            self.font
                .draw_centered(pm, rect.x, rect.y, rect.w, rect.h, 12.0, text_color, label);
        }
    }

    fn draw_mode_button(
        &self,
        pm: &mut Pixmap,
        rect: UiRect,
        active: bool,
        hovered: bool,
        active_color: Color,
        icon: IconKind,
    ) {
        let bg = if active {
            active_color
        } else if hovered {
            Color::from_rgba8(255, 255, 255, 28)
        } else {
            Color::TRANSPARENT
        };
        if bg != Color::TRANSPARENT {
            fill_rounded_rect(pm, rect.x, rect.y, rect.w, rect.h, 13.0, bg);
        }
        let fg = if active || hovered {
            Color::WHITE
        } else {
            Color::from_rgba8(190, 195, 205, 220)
        };
        draw_vector_icon(pm, icon, rect.x + rect.w * 0.5, rect.y + rect.h * 0.5, fg);
    }

    fn handle_hud_button(&mut self, btn: HudButton) {
        match btn {
            HudButton::TargetSelection => self.kind = CaptureKind::Selection,
            HudButton::TargetScreen => self.kind = CaptureKind::Screen,
            HudButton::TargetWindow => self.kind = CaptureKind::Window,
            HudButton::TogglePointer => self.show_pointer = !self.show_pointer,
            HudButton::Close => {
                self.confirmed = false;
                self.finished = true;
            }
            HudButton::ModeScreenshot => self.action = CaptureAction::Screenshot,
            HudButton::ModeRecord => {
                self.action = CaptureAction::Record;
                self.show_pointer = true;
            }
            HudButton::Shutter => {
                self.confirmed = true;
                self.finished = true;
            }
            HudButton::ToggleAudio => self.audio_system = !self.audio_system,
            HudButton::ToggleMic => self.audio_mic = !self.audio_mic,
            HudButton::ToggleFps => self.fps = if self.fps == 30 { 60 } else { 30 },
        }
        self.needs_redraw = true;
    }

    fn on_pointer_motion(&mut self, x: f32, y: f32) {
        self.pointer_x = x;
        self.pointer_y = y;

        let hud = HudLayout::compute(self.surf_w as f32, self.surf_h as f32);
        let new_hover = hud.hit_test(x, y, self.action);
        if new_hover != self.hovered_button {
            self.hovered_button = new_hover;
            self.needs_redraw = true;
        }

        match self.drag {
            DragState::None => {
                if self.kind == CaptureKind::Window {
                    self.needs_redraw = true;
                }
            }
            DragState::MoveSelection {
                start_x,
                start_y,
                orig,
            } => {
                let dx = (x - start_x).round() as i32;
                let dy = (y - start_y).round() as i32;
                let max_x = (self.surf_w as i32 - orig.w as i32).max(0);
                let max_y = (self.surf_h as i32 - orig.h as i32).max(0);
                self.selection = Rect {
                    x: (orig.x + dx).clamp(0, max_x),
                    y: (orig.y + dy).clamp(0, max_y),
                    w: orig.w,
                    h: orig.h,
                };
                self.needs_redraw = true;
            }
            DragState::NewSelection { anchor_x, anchor_y } => {
                let cx = x.clamp(0.0, self.surf_w as f32);
                let cy = y.clamp(0.0, self.surf_h as f32);
                let min_x = anchor_x.min(cx).round() as i32;
                let min_y = anchor_y.min(cy).round() as i32;
                let max_x = anchor_x.max(cx).round() as i32;
                let max_y = anchor_y.max(cy).round() as i32;
                self.selection = Rect {
                    x: min_x,
                    y: min_y,
                    w: (max_x - min_x).max(24) as u32,
                    h: (max_y - min_y).max(24) as u32,
                };
                self.needs_redraw = true;
            }
            DragState::ResizeSelection { handle, orig } => {
                self.selection =
                    apply_resize(orig, handle, x, y, self.surf_w as i32, self.surf_h as i32);
                self.needs_redraw = true;
            }
        }
    }

    fn on_pointer_button(&mut self, button: u32, pressed: bool) {
        if button != BTN_LEFT_MOUSE {
            return;
        }
        let x = self.pointer_x;
        let y = self.pointer_y;

        if !pressed {
            if !matches!(self.drag, DragState::None) {
                self.drag = DragState::None;
                self.needs_redraw = true;
            }
            return;
        }

        let hud = HudLayout::compute(self.surf_w as f32, self.surf_h as f32);
        if let Some(btn) = hud.hit_test(x, y, self.action) {
            self.handle_hud_button(btn);
            return;
        }
        if hud.panel.contains(x, y) {
            return;
        }

        // Handle multi-monitor pills in Screen mode.
        if self.kind == CaptureKind::Screen && self.outputs.len() > 1 {
            let pill_h = 30.0;
            let gap = 10.0;
            let pill_w = 154.0;
            let total_w = self.outputs.len() as f32 * pill_w + (self.outputs.len() - 1) as f32 * gap;
            let start_x = ((self.surf_w as f32 - total_w) * 0.5).max(12.0);
            let py = (hud.panel.y - pill_h - 14.0).max(12.0);
            for i in 0..self.outputs.len() {
                let pr = UiRect {
                    x: start_x + i as f32 * (pill_w + gap),
                    y: py,
                    w: pill_w,
                    h: pill_h,
                };
                if pr.contains(x, y) {
                    self.selected_output_idx = i;
                    self.needs_redraw = true;
                    return;
                }
            }
        }

        // Handle window rows in Window mode.
        if self.kind == CaptureKind::Window && !self.toplevels.is_empty() {
            let card = self.window_picker_rect(self.surf_w as f32, self.surf_h as f32);
            let max_rows = self.toplevels.len().min(6);
            for i in 0..max_rows {
                let row = UiRect {
                    x: card.x + 16.0,
                    y: card.y + 52.0 + i as f32 * 48.0,
                    w: card.w - 32.0,
                    h: 42.0,
                };
                if row.contains(x, y) {
                    self.selected_window_idx = i;
                    self.needs_redraw = true;
                    return;
                }
            }
        }

        if self.kind == CaptureKind::Selection {
            if let Some(handle) = hit_selection_handle(self.selection, x, y) {
                self.drag = DragState::ResizeSelection {
                    handle,
                    orig: self.selection,
                };
                return;
            }
            let sel_rect = UiRect {
                x: self.selection.x as f32,
                y: self.selection.y as f32,
                w: self.selection.w as f32,
                h: self.selection.h as f32,
            };
            if sel_rect.contains(x, y) {
                self.drag = DragState::MoveSelection {
                    start_x: x,
                    start_y: y,
                    orig: self.selection,
                };
            } else {
                self.drag = DragState::NewSelection {
                    anchor_x: x,
                    anchor_y: y,
                };
                self.selection = Rect {
                    x: x.round() as i32,
                    y: y.round() as i32,
                    w: 24,
                    h: 24,
                };
                self.needs_redraw = true;
            }
        }
    }

    fn desired_cursor_shape(&self) -> CursorShape {
        let hud = HudLayout::compute(self.surf_w as f32, self.surf_h as f32);
        if hud.hit_test(self.pointer_x, self.pointer_y, self.action).is_some() {
            return CursorShape::Pointer;
        }
        if hud.panel.contains(self.pointer_x, self.pointer_y) {
            return CursorShape::Default;
        }
        if self.kind == CaptureKind::Selection {
            if let Some(handle) = hit_selection_handle(self.selection, self.pointer_x, self.pointer_y) {
                return match handle {
                    HandleKind::Nw | HandleKind::Se => CursorShape::NwseResize,
                    HandleKind::Ne | HandleKind::Sw => CursorShape::NeswResize,
                    HandleKind::N | HandleKind::S => CursorShape::NsResize,
                    HandleKind::E | HandleKind::W => CursorShape::EwResize,
                };
            }
            let sel = UiRect {
                x: self.selection.x as f32,
                y: self.selection.y as f32,
                w: self.selection.w as f32,
                h: self.selection.h as f32,
            };
            if sel.contains(self.pointer_x, self.pointer_y) {
                return CursorShape::Move;
            }
            return CursorShape::Crosshair;
        }
        CursorShape::Default
    }

    fn update_cursor_shape(&mut self, conn: &Connection) {
        let desired = self.desired_cursor_shape();
        if desired == self.last_cursor || self.pointer_enter_serial == 0 {
            return;
        }
        if let Some(dev) = &self.cursor_device {
            dev.set_shape(self.pointer_enter_serial, desired);
            let _ = conn.flush();
            self.last_cursor = desired;
        }
    }

    fn on_key(&mut self, key: u32) {
        match key {
            1 => {
                // ESC
                self.confirmed = false;
                self.finished = true;
            }
            28 | 96 | 57 => {
                // Enter / KP_Enter / Space
                self.confirmed = true;
                self.finished = true;
            }
            15 | 47 => {
                // Tab / V: toggle Screenshot <-> Record
                self.action = if self.action == CaptureAction::Screenshot {
                    self.show_pointer = true;
                    CaptureAction::Record
                } else {
                    CaptureAction::Screenshot
                };
                self.needs_redraw = true;
            }
            2 => {
                self.kind = CaptureKind::Selection;
                self.needs_redraw = true;
            }
            3 => {
                self.kind = CaptureKind::Screen;
                self.needs_redraw = true;
            }
            4 => {
                self.kind = CaptureKind::Window;
                self.needs_redraw = true;
            }
            25 => {
                // P
                self.show_pointer = !self.show_pointer;
                self.needs_redraw = true;
            }
            30 => {
                // A
                self.audio_system = !self.audio_system;
                self.needs_redraw = true;
            }
            50 => {
                // M
                self.audio_mic = !self.audio_mic;
                self.needs_redraw = true;
            }
            33 => {
                // F
                self.fps = if self.fps == 30 { 60 } else { 30 };
                self.needs_redraw = true;
            }
            103 => {
                // Up arrow
                if self.kind == CaptureKind::Window && !self.toplevels.is_empty() {
                    let count = self.toplevels.len().min(6);
                    self.selected_window_idx = (self.selected_window_idx + count - 1) % count;
                    self.needs_redraw = true;
                }
            }
            108 => {
                // Down arrow
                if self.kind == CaptureKind::Window && !self.toplevels.is_empty() {
                    let count = self.toplevels.len().min(6);
                    self.selected_window_idx = (self.selected_window_idx + 1) % count;
                    self.needs_redraw = true;
                }
            }
            _ => {}
        }
    }
}

fn selection_handles(r: Rect) -> [(HandleKind, f32, f32); 8] {
    let x0 = r.x as f32;
    let y0 = r.y as f32;
    let xm = x0 + r.w as f32 * 0.5;
    let ym = y0 + r.h as f32 * 0.5;
    let x1 = x0 + r.w as f32;
    let y1 = y0 + r.h as f32;
    [
        (HandleKind::Nw, x0, y0),
        (HandleKind::N, xm, y0),
        (HandleKind::Ne, x1, y0),
        (HandleKind::E, x1, ym),
        (HandleKind::Se, x1, y1),
        (HandleKind::S, xm, y1),
        (HandleKind::Sw, x0, y1),
        (HandleKind::W, x0, ym),
    ]
}

fn hit_selection_handle(r: Rect, px: f32, py: f32) -> Option<HandleKind> {
    for (kind, hx, hy) in selection_handles(r) {
        let dx = px - hx;
        let dy = py - hy;
        if dx * dx + dy * dy <= 14.0 * 14.0 {
            return Some(kind);
        }
    }
    None
}

fn apply_resize(orig: Rect, handle: HandleKind, px: f32, py: f32, max_w: i32, max_h: i32) -> Rect {
    let min_size = 24;
    let mut left = orig.x;
    let mut top = orig.y;
    let mut right = orig.x + orig.w as i32;
    let mut bottom = orig.y + orig.h as i32;
    let cx = (px.round() as i32).clamp(0, max_w);
    let cy = (py.round() as i32).clamp(0, max_h);

    match handle {
        HandleKind::Nw => {
            left = cx.min(right - min_size);
            top = cy.min(bottom - min_size);
        }
        HandleKind::N => {
            top = cy.min(bottom - min_size);
        }
        HandleKind::Ne => {
            right = cx.max(left + min_size);
            top = cy.min(bottom - min_size);
        }
        HandleKind::E => {
            right = cx.max(left + min_size);
        }
        HandleKind::Se => {
            right = cx.max(left + min_size);
            bottom = cy.max(top + min_size);
        }
        HandleKind::S => {
            bottom = cy.max(top + min_size);
        }
        HandleKind::Sw => {
            left = cx.min(right - min_size);
            bottom = cy.max(top + min_size);
        }
        HandleKind::W => {
            left = cx.min(right - min_size);
        }
    }

    Rect {
        x: left,
        y: top,
        w: (right - left).max(min_size) as u32,
        h: (bottom - top).max(min_size) as u32,
    }
}

fn frame_to_pixmap(frame: &CapturedFrame) -> Option<Pixmap> {
    let mut pm = Pixmap::new(frame.width, frame.height)?;
    let dst = pm.data_mut();
    for (s, d) in frame.data.chunks_exact(4).zip(dst.chunks_exact_mut(4)) {
        match frame.layout {
            PixelLayout::Bgrx => {
                d[0] = s[2];
                d[1] = s[1];
                d[2] = s[0];
                d[3] = 255;
            }
            PixelLayout::Rgbx => {
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = 255;
            }
        }
    }
    Some(pm)
}

#[derive(Clone, Copy)]
enum IconKind {
    Selection,
    Screen,
    Window,
    Pointer,
    Camera,
    Video,
}

fn draw_vector_icon(pm: &mut Pixmap, icon: IconKind, cx: f32, cy: f32, color: Color) {
    match icon {
        IconKind::Selection => {
            stroke_rounded_rect(pm, cx - 6.0, cy - 5.0, 12.0, 10.0, 2.0, 1.4, color);
        }
        IconKind::Screen => {
            stroke_rounded_rect(pm, cx - 7.0, cy - 5.5, 14.0, 9.0, 1.8, 1.4, color);
            draw_line(pm, cx - 3.5, cy + 5.5, cx + 3.5, cy + 5.5, 1.5, color);
        }
        IconKind::Window => {
            stroke_rounded_rect(pm, cx - 6.5, cy - 5.5, 13.0, 11.0, 2.0, 1.4, color);
            draw_line(pm, cx - 6.0, cy - 2.0, cx + 6.0, cy - 2.0, 1.2, color);
        }
        IconKind::Pointer => {
            let mut pb = PathBuilder::new();
            pb.move_to(cx - 3.5, cy - 5.5);
            pb.line_to(cx - 3.5, cy + 4.5);
            pb.line_to(cx - 0.5, cy + 2.0);
            pb.line_to(cx + 2.0, cy + 5.5);
            pb.line_to(cx + 4.0, cy + 4.5);
            pb.line_to(cx + 1.5, cy + 1.0);
            pb.line_to(cx + 4.5, cy + 0.5);
            pb.close();
            if let Some(path) = pb.finish() {
                let mut paint = Paint::default();
                paint.set_color(color);
                paint.anti_alias = true;
                pm.fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
            }
        }
        IconKind::Camera => {
            stroke_rounded_rect(pm, cx - 7.5, cy - 4.5, 15.0, 10.5, 2.5, 1.5, color);
            fill_rounded_rect(pm, cx - 3.0, cy - 7.0, 6.0, 2.5, 1.0, color);
            stroke_circle(pm, cx, cy + 0.8, 3.0, 1.4, color);
        }
        IconKind::Video => {
            stroke_rounded_rect(pm, cx - 8.5, cy - 4.5, 11.5, 9.0, 2.0, 1.5, color);
            let mut pb = PathBuilder::new();
            pb.move_to(cx + 3.5, cy - 1.5);
            pb.line_to(cx + 8.5, cy - 4.0);
            pb.line_to(cx + 8.5, cy + 4.0);
            pb.line_to(cx + 3.5, cy + 1.5);
            pb.close();
            if let Some(path) = pb.finish() {
                let mut paint = Paint::default();
                paint.set_color(color);
                paint.anti_alias = true;
                pm.fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
            }
        }
    }
}

/// Fills an axis-aligned rectangle.
pub fn fill_rect(pm: &mut Pixmap, x: f32, y: f32, w: f32, h: f32, color: Color) {
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    if let Some(rect) = SkRect::from_xywh(x, y, w, h) {
        let mut paint = Paint::default();
        paint.set_color(color);
        pm.fill_rect(rect, &paint, Transform::identity(), None);
    }
}

/// Strokes an axis-aligned rectangle border.
pub fn stroke_rect(pm: &mut Pixmap, x: f32, y: f32, w: f32, h: f32, width: f32, color: Color) {
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    if let Some(rect) = SkRect::from_xywh(x, y, w, h) {
        let mut pb = PathBuilder::new();
        pb.push_rect(rect);
        if let Some(path) = pb.finish() {
            let mut paint = Paint::default();
            paint.set_color(color);
            let stroke = Stroke {
                width,
                ..Stroke::default()
            };
            pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
        }
    }
}

/// Fills a rounded rectangle.
pub fn fill_rounded_rect(pm: &mut Pixmap, x: f32, y: f32, w: f32, h: f32, r: f32, color: Color) {
    if let Some(path) = rounded_rect_path(x, y, w, h, r) {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        pm.fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
    }
}

/// Strokes a rounded rectangle outline.
pub fn stroke_rounded_rect(
    pm: &mut Pixmap,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    r: f32,
    width: f32,
    color: Color,
) {
    if let Some(path) = rounded_rect_path(x, y, w, h, r) {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        let stroke = Stroke {
            width,
            ..Stroke::default()
        };
        pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
    }
}

/// Fills a circle centered at `(cx, cy)` with radius `r`.
pub fn fill_circle(pm: &mut Pixmap, cx: f32, cy: f32, r: f32, color: Color) {
    if let Some(path) = PathBuilder::from_circle(cx, cy, r) {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        pm.fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
    }
}

/// Strokes a circle outline centered at `(cx, cy)` with radius `r`.
pub fn stroke_circle(pm: &mut Pixmap, cx: f32, cy: f32, r: f32, width: f32, color: Color) {
    if let Some(path) = PathBuilder::from_circle(cx, cy, r) {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        let stroke = Stroke {
            width,
            ..Stroke::default()
        };
        pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
    }
}

/// Draws a straight line segment.
pub fn draw_line(
    pm: &mut Pixmap,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    width: f32,
    color: Color,
) {
    let mut pb = PathBuilder::new();
    pb.move_to(x0, y0);
    pb.line_to(x1, y1);
    if let Some(path) = pb.finish() {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        let stroke = Stroke {
            width,
            line_cap: LineCap::Round,
            ..Stroke::default()
        };
        pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
    }
}

fn rounded_rect_path(x: f32, y: f32, w: f32, h: f32, r: f32) -> Option<tiny_skia::Path> {
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    let rad = r.min(w * 0.5).min(h * 0.5).max(0.0);
    let k = rad * 0.552_284_8;
    let mut pb = PathBuilder::new();
    pb.move_to(x + rad, y);
    pb.line_to(x + w - rad, y);
    pb.cubic_to(x + w - rad + k, y, x + w, y + rad - k, x + w, y + rad);
    pb.line_to(x + w, y + h - rad);
    pb.cubic_to(
        x + w,
        y + h - rad + k,
        x + w - rad + k,
        y + h,
        x + w - rad,
        y + h,
    );
    pb.line_to(x + rad, y + h);
    pb.cubic_to(x + rad - k, y + h, x, y + h - rad + k, x, y + h - rad);
    pb.line_to(x, y + rad);
    pb.cubic_to(x, y + rad - k, x + rad - k, y, x + rad, y);
    pb.close();
    pb.finish()
}

impl Dispatch<WlRegistry, ()> for OverlayState {
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

impl Dispatch<WlCompositor, ()> for OverlayState {
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

impl Dispatch<WlSurface, ()> for OverlayState {
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

impl Dispatch<ZwlrLayerShellV1, ()> for OverlayState {
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

impl Dispatch<ZwlrLayerSurfaceV1, ()> for OverlayState {
    fn event(
        state: &mut Self,
        layer_surface: &ZwlrLayerSurfaceV1,
        event: zwlr_layer_surface_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_layer_surface_v1::Event::Configure {
                serial,
                width,
                height,
            } => {
                layer_surface.ack_configure(serial);
                let fallback_w = state
                    .outputs
                    .first()
                    .map(|o| o.logical_w.max(640) as u32)
                    .unwrap_or(1920);
                let fallback_h = state
                    .outputs
                    .first()
                    .map(|o| o.logical_h.max(480) as u32)
                    .unwrap_or(1080);
                state.surf_w = if width > 0 { width } else { fallback_w };
                state.surf_h = if height > 0 { height } else { fallback_h };
                state.configured = true;
                state.needs_redraw = true;
            }
            zwlr_layer_surface_v1::Event::Closed => {
                state.closed = true;
            }
            _ => {}
        }
    }
}

impl Dispatch<WlShm, ()> for OverlayState {
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

impl Dispatch<WlShmPool, ()> for OverlayState {
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

impl Dispatch<WlBuffer, ()> for OverlayState {
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

impl Dispatch<WlSeat, ()> for OverlayState {
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
                if caps.contains(Capability::Keyboard) && state.keyboard.is_none() {
                    state.keyboard = Some(seat.get_keyboard(qh, ()));
                }
            }
        }
    }
}

impl Dispatch<WlPointer, ()> for OverlayState {
    fn event(
        state: &mut Self,
        _: &WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter {
                serial,
                surface_x,
                surface_y,
                ..
            } => {
                state.pointer_enter_serial = serial;
                state.last_cursor = CursorShape::Wait; // Force re-application on enter.
                state.on_pointer_motion(surface_x as f32, surface_y as f32);
            }
            wl_pointer::Event::Motion {
                surface_x,
                surface_y,
                ..
            } => {
                state.on_pointer_motion(surface_x as f32, surface_y as f32);
            }
            wl_pointer::Event::Button {
                button,
                state: btn_state,
                ..
            } => {
                if let WEnum::Value(st) = btn_state {
                    state.on_pointer_button(button, st == ButtonState::Pressed);
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<WlKeyboard, ()> for OverlayState {
    fn event(
        state: &mut Self,
        _: &WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_keyboard::Event::Key {
            key,
            state: key_state,
            ..
        } = event
        {
            if let WEnum::Value(KeyState::Pressed) = key_state {
                state.on_key(key);
            }
        }
    }
}

impl Dispatch<WpCursorShapeManagerV1, ()> for OverlayState {
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

impl Dispatch<WpCursorShapeDeviceV1, ()> for OverlayState {
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
