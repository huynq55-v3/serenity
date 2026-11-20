use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use smithay::{
    backend::{
        allocator::{
            Fourcc,
            gbm::{GbmAllocator, GbmBufferFlags, GbmDevice},
        },
        drm::{
            DrmDevice, DrmDeviceFd, DrmEvent,
            compositor::{DrmCompositor, FrameFlags},
            exporter::gbm::GbmFramebufferExporter,
        },
        egl::{EGLContext, EGLDisplay},
        libinput::LibinputInputBackend,
        renderer::{
            Color32F, ImportDma, element::surface::WaylandSurfaceRenderElement, gles::GlesRenderer,
        },
    },
    desktop::space::{SpaceRenderElements, space_render_elements},
    output::{Mode as OutputMode, Output, PhysicalProperties, Subpixel},
    reexports::{
        calloop::EventLoop,
        drm::control::{Device as ControlDevice, connector},
        input::{Libinput, LibinputInterface},
        wayland_server::Display,
    },
    utils::{DeviceFd, Transform},
};
use tracing::{error, info, warn};

use crate::input::handle_input;
use crate::state::SerenityState;

/// Direct `/dev/input/event*` opener for non-root user in the `input` group
/// (works on minimal Serenity OS without requiring `systemd-logind` or `seatd`).
struct DirectLibinputInterface;

impl LibinputInterface for DirectLibinputInterface {
    fn open_restricted(&mut self, path: &Path, flags: i32) -> Result<OwnedFd, i32> {
        OpenOptions::new()
            .custom_flags(flags)
            .read((flags & libc::O_RDONLY != 0) || (flags & libc::O_RDWR != 0))
            .write((flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0))
            .open(path)
            .map(Into::into)
            .map_err(|err| err.raw_os_error().unwrap_or(libc::EACCES))
    }

    fn close_restricted(&mut self, fd: OwnedFd) {
        drop(fd);
    }
}

fn find_drm_card() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(explicit) = std::env::var("SERENITY_DRM_CARD") {
        let p = PathBuf::from(explicit);
        if p.exists() {
            return Ok(p);
        }
    }
    let mut cards: Vec<PathBuf> = fs::read_dir("/dev/dri")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with("card"))
        })
        .collect();
    cards.sort();
    cards
        .into_iter()
        .next()
        .ok_or_else(|| "No /dev/dri/card* DRM device found".into())
}

fn attach_input_devices(libinput: &mut Libinput) -> usize {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir("/dev/input") {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.starts_with("event"))
            })
            .collect();
        paths.sort();
        for p in paths {
            if let Some(s) = p.to_str() {
                if libinput.path_add_device(s).is_some() {
                    count += 1;
                }
            }
        }
    }
    count
}

pub fn run(client_cmd: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let card_path = find_drm_card()?;
    info!("Opening DRM device: {}", card_path.display());

    let raw_file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&card_path)?;
    let device_fd = DeviceFd::from(OwnedFd::from(raw_file));
    let drm_fd = DrmDeviceFd::new(device_fd);

    let (mut drm, drm_notifier) = DrmDevice::new(drm_fd.clone(), false)?;
    let gbm = GbmDevice::new(drm_fd.clone())?;
    let egl_display = unsafe { EGLDisplay::new(gbm.clone())? };
    let egl_context = EGLContext::new(&egl_display)?;
    let mut renderer = unsafe { GlesRenderer::new(egl_context)? };

    // Discover first connected display connector, preferred mode, and CRTC.
    let res_handles = drm.resource_handles()?;
    let mut selected = None;
    for &conn_handle in res_handles.connectors() {
        let conn_info = drm.get_connector(conn_handle, true)?;
        if conn_info.state() != connector::State::Connected {
            continue;
        }
        let Some(&mode) = conn_info.modes().first() else {
            continue;
        };
        let mut crtc_handle = None;
        for &enc_handle in conn_info.encoders() {
            if let Ok(enc_info) = drm.get_encoder(enc_handle) {
                if let Some(c) = enc_info.crtc() {
                    crtc_handle = Some(c);
                    break;
                }
                if let Some(c) = res_handles
                    .filter_crtcs(enc_info.possible_crtcs())
                    .into_iter()
                    .next()
                {
                    crtc_handle = Some(c);
                    break;
                }
            }
        }
        if let Some(crtc) = crtc_handle {
            selected = Some((conn_handle, conn_info, mode, crtc));
            break;
        }
    }

    let (conn_handle, conn_info, drm_mode, crtc) =
        selected.ok_or("No connected DRM monitor/CRTC found")?;

    let (w, h) = drm_mode.size();
    let refresh_mhz = (drm_mode.vrefresh() * 1000) as i32;
    let conn_name = format!("{:?}-{}", conn_info.interface(), conn_info.interface_id());
    info!(
        "DRM output selected: {} ({}x{} @ {}Hz)",
        conn_name,
        w,
        h,
        drm_mode.vrefresh()
    );

    let surface = drm.create_surface(crtc, drm_mode, &[conn_handle])?;
    let gbm_allocator = GbmAllocator::new(
        gbm.clone(),
        GbmBufferFlags::RENDERING | GbmBufferFlags::SCANOUT,
    );
    let framebuffer_exporter = GbmFramebufferExporter::new(gbm.clone(), None.into());
    let color_formats = [Fourcc::Argb8888, Fourcc::Xrgb8888];
    let renderer_formats = renderer.dmabuf_formats();

    let mut event_loop: EventLoop<SerenityState> = EventLoop::try_new()?;
    let display: Display<SerenityState> = Display::new()?;
    let mut state = SerenityState::new(&event_loop.handle(), event_loop.get_signal(), display)?;

    let output_mode = OutputMode {
        size: (w as i32, h as i32).into(),
        refresh: refresh_mhz,
    };
    let output = Output::new(
        conn_name,
        PhysicalProperties {
            size: (
                conn_info.size().map(|s| s.0 as i32).unwrap_or(0),
                conn_info.size().map(|s| s.1 as i32).unwrap_or(0),
            )
                .into(),
            subpixel: Subpixel::Unknown,
            make: "Serenity".into(),
            model: "DRM/KMS".into(),
        },
    );
    let _global = output.create_global::<SerenityState>(&state.display_handle);
    output.change_current_state(Some(output_mode), Some(Transform::Normal), None, Some((0, 0).into()));
    output.set_preferred(output_mode);
    state.space.map_output(&output, (0, 0));

    let mut drm_compositor = DrmCompositor::new(
        &output,
        surface,
        None,
        gbm_allocator,
        framebuffer_exporter,
        color_formats,
        renderer_formats,
        drm.cursor_size(),
        Some(gbm),
    )?;

    // Initialize libinput directly over /dev/input/event*
    let mut libinput_ctx = Libinput::new_from_path(DirectLibinputInterface);
    let dev_count = attach_input_devices(&mut libinput_ctx);
    info!("libinput attached {} input device(s) from /dev/input/event*", dev_count);
    let input_backend = LibinputInputBackend::new(libinput_ctx);

    let output_for_input = output.clone();
    event_loop
        .handle()
        .insert_source(input_backend, move |event, _, state| {
            handle_input(state, event, &output_for_input);
        })?;

    let socket_str = state.socket_name.to_string_lossy().into_owned();
    info!(
        "Serenity DRM/KMS Compositor listening on WAYLAND_DISPLAY={} (Ctrl+Alt+Backspace to quit)",
        socket_str
    );

    if !client_cmd.is_empty() {
        info!("Spawning initial Wayland client: {:?}", client_cmd);
        let mut cmd = Command::new(&client_cmd[0]);
        cmd.args(&client_cmd[1..]);
        cmd.env("WAYLAND_DISPLAY", &socket_str);
        if let Err(e) = cmd.spawn() {
            error!("Failed to spawn client '{}': {}", client_cmd[0], e);
        }
    }

    let bg_color = Color32F::new(0.07, 0.09, 0.14, 1.0);

    // Render initial frame to kick off the VBlank loop.
    render_drm_frame(&mut drm_compositor, &mut renderer, &mut state, &output, bg_color);

    let output_for_drm = output.clone();
    event_loop
        .handle()
        .insert_source(drm_notifier, move |event, _, state| match event {
            DrmEvent::VBlank(_) => {
                if let Err(e) = drm_compositor.frame_submitted() {
                    warn!("DRM frame_submitted error: {}", e);
                }
                render_drm_frame(
                    &mut drm_compositor,
                    &mut renderer,
                    state,
                    &output_for_drm,
                    bg_color,
                );
            }
            DrmEvent::Error(e) => {
                error!("DRM device error: {}", e);
            }
        })?;

    event_loop.run(Some(Duration::from_millis(16)), &mut state, |state| {
        state.space.refresh();
        let _ = state.display_handle.flush_clients();
    })?;

    Ok(())
}

fn render_drm_frame(
    drm_compositor: &mut DrmCompositor<
        GbmAllocator<DrmDeviceFd>,
        GbmFramebufferExporter<DrmDeviceFd>,
        (),
        DrmDeviceFd,
    >,
    renderer: &mut GlesRenderer,
    state: &mut SerenityState,
    output: &Output,
    bg_color: Color32F,
) {
    let elements: Vec<SpaceRenderElements<GlesRenderer, WaylandSurfaceRenderElement<GlesRenderer>>> =
        space_render_elements(renderer, [&state.space], output, 1.0).unwrap_or_default();

    if let Err(e) = drm_compositor.render_frame(renderer, &elements, bg_color, FrameFlags::DEFAULT) {
        warn!("DRM render_frame failed: {}", e);
        return;
    }
    if let Err(e) = drm_compositor.queue_frame(()) {
        warn!("DRM queue_frame failed: {}", e);
    }

    state.space.elements().for_each(|window| {
        window.send_frame(
            output,
            state.start_time.elapsed(),
            Some(Duration::ZERO),
            |_, _| Some(output.clone()),
        );
    });
    let _ = state.display_handle.flush_clients();
}
