mod drm_backend;
mod input;
mod state;

use std::process::Command;
use std::time::Duration;

use smithay::{
    backend::{
        renderer::{
            Color32F, damage::OutputDamageTracker, element::surface::WaylandSurfaceRenderElement,
            gles::GlesRenderer,
        },
        winit::{self, WinitEvent},
    },
    desktop::space::render_output,
    output::{Mode, Output, PhysicalProperties, Subpixel},
    reexports::{calloop::EventLoop, wayland_server::Display},
    utils::Transform,
};
use tracing::{error, info};

use input::handle_input;
use state::SerenityState;

fn enforce_non_root(allow_root: bool) {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 && !allow_root {
        eprintln!(
            "[serenity-compositor] REFUSED to start as root (UID 0).\n\
             Desktop sessions must run as an unprivileged user (e.g. 'serenity', UID 1000).\n\
             Pass --allow-root only for low-level debugging."
        );
        std::process::exit(1);
    }
}

fn run_winit(client_cmd: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_loop: EventLoop<SerenityState> = EventLoop::try_new()?;
    let display: Display<SerenityState> = Display::new()?;
    let mut state = SerenityState::new(&event_loop.handle(), event_loop.get_signal(), display)?;

    let (mut backend, winit_evt_loop) = winit::init::<GlesRenderer>()?;

    let mode = Mode {
        size: backend.window_size(),
        refresh: 60_000,
    };
    let output = Output::new(
        "SERENITY-1".to_string(),
        PhysicalProperties {
            size: (0, 0).into(),
            subpixel: Subpixel::Unknown,
            make: "Serenity".into(),
            model: "Smithay-Winit".into(),
        },
    );
    let _global = output.create_global::<SerenityState>(&state.display_handle);
    output.change_current_state(Some(mode), Some(Transform::Flipped180), None, Some((0, 0).into()));
    output.set_preferred(mode);
    state.space.map_output(&output, (0, 0));

    let mut damage_tracker = OutputDamageTracker::from_output(&output);

    let socket_str = state.socket_name.to_string_lossy().into_owned();
    info!(
        "Serenity Wayland Compositor (Winit nested) listening on WAYLAND_DISPLAY={}",
        socket_str
    );
    println!("WAYLAND_DISPLAY={}", socket_str);

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

    event_loop
        .handle()
        .insert_source(winit_evt_loop, move |event, _, state| match event {
            WinitEvent::Resized { size, .. } => {
                output.change_current_state(
                    Some(Mode {
                        size,
                        refresh: 60_000,
                    }),
                    None,
                    None,
                    None,
                );
            }
            WinitEvent::Input(input_event) => handle_input(state, input_event, &output),
            WinitEvent::Redraw => {
                let size = backend.window_size();
                let damage = smithay::utils::Rectangle::from_size(size);
                if let Ok((renderer, mut framebuffer)) = backend.bind() {
                    let _ = render_output::<_, WaylandSurfaceRenderElement<GlesRenderer>, _, _>(
                        &output,
                        renderer,
                        &mut framebuffer,
                        1.0,
                        0,
                        [&state.space],
                        &[],
                        &mut damage_tracker,
                        bg_color,
                    );
                }
                let _ = backend.submit(Some(&[damage]));

                state.space.elements().for_each(|window| {
                    window.send_frame(
                        &output,
                        state.start_time.elapsed(),
                        Some(Duration::ZERO),
                        |_, _| Some(output.clone()),
                    );
                });
                state.space.refresh();
                let _ = state.display_handle.flush_clients();
                backend.window().request_redraw();
            }
            WinitEvent::CloseRequested => {
                info!("Close requested, shutting down Serenity Compositor.");
                state.loop_signal.stop();
            }
            WinitEvent::Focus(_) => {}
        })?;

    event_loop.run(None, &mut state, |state| {
        state.space.refresh();
        let _ = state.display_handle.flush_clients();
    })?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "serenity_compositor=info,smithay=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let allow_root = args.iter().any(|a| a == "--allow-root");
    let force_drm = args.iter().any(|a| a == "--drm");
    let force_winit = args.iter().any(|a| a == "--winit");
    enforce_non_root(allow_root);

    let client_cmd: Vec<String> = args
        .iter()
        .position(|a| a == "--")
        .map(|idx| args[idx + 1..].to_vec())
        .unwrap_or_default();

    let has_host_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();

    if force_drm || (!force_winit && !has_host_display) {
        info!("Starting Serenity Compositor in bare-metal DRM/KMS + libinput mode");
        drm_backend::run(&client_cmd)
    } else {
        info!("Starting Serenity Compositor in nested Winit mode");
        run_winit(&client_cmd)
    }
}
