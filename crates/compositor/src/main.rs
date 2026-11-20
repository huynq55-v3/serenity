mod state;

use std::process::Command;
use std::time::Duration;

use smithay::{
    backend::{
        input::{
            AbsolutePositionEvent, Axis, ButtonState, Event, InputEvent, KeyboardKeyEvent,
            PointerAxisEvent, PointerButtonEvent,
        },
        renderer::{
            Color32F, damage::OutputDamageTracker, element::surface::WaylandSurfaceRenderElement,
            gles::GlesRenderer,
        },
        winit::{self, WinitEvent},
    },
    desktop::space::render_output,
    input::{
        keyboard::FilterResult,
        pointer::{AxisFrame, ButtonEvent, MotionEvent},
    },
    output::{Mode, Output, PhysicalProperties, Subpixel},
    reexports::{calloop::EventLoop, wayland_server::Display},
    utils::{SERIAL_COUNTER, Transform},
};
use state::SerenityState;
use tracing::{error, info};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "serenity_compositor=info,smithay=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let allow_root = args.iter().any(|a| a == "--allow-root");
    enforce_non_root(allow_root);

    // Optional initial client command passed after `--` (e.g. `serenity-compositor -- foot`)
    let client_cmd: Vec<String> = args
        .iter()
        .position(|a| a == "--")
        .map(|idx| args[idx + 1..].to_vec())
        .unwrap_or_default();

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
        "Serenity Wayland Compositor (Smithay 0.7) listening on WAYLAND_DISPLAY={}",
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

    // Serenity dark slate background
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

fn handle_input(
    state: &mut SerenityState,
    event: InputEvent<winit::WinitInput>,
    output: &Output,
) {
    match event {
        InputEvent::Keyboard { event } => {
            let serial = SERIAL_COUNTER.next_serial();
            let time = Event::time_msec(&event);
            if let Some(keyboard) = state.seat.get_keyboard() {
                keyboard.input::<(), _>(
                    state,
                    event.key_code(),
                    event.state(),
                    serial,
                    time,
                    |_, _, _| FilterResult::Forward,
                );
            }
        }
        InputEvent::PointerMotionAbsolute { event } => {
            let output_geo = state.space.output_geometry(output).unwrap_or_default();
            let pos = event.position_transformed(output_geo.size) + output_geo.loc.to_f64();
            state.pointer_location = pos;
            let serial = SERIAL_COUNTER.next_serial();
            let under = state.surface_under(pos);
            if let Some(pointer) = state.seat.get_pointer() {
                pointer.motion(
                    state,
                    under,
                    &MotionEvent {
                        location: pos,
                        serial,
                        time: event.time_msec(),
                    },
                );
                pointer.frame(state);
            }
        }
        InputEvent::PointerButton { event } => {
            let serial = SERIAL_COUNTER.next_serial();
            let button = event.button_code();
            let button_state = event.state();

            if button_state == ButtonState::Pressed {
                let under = state.space.element_under(state.pointer_location).map(|(w, _)| w.clone());
                if let Some(window) = under {
                    state.space.raise_element(&window, true);
                    if let Some(toplevel) = window.toplevel() {
                        if let Some(kb) = state.seat.get_keyboard() {
                            kb.set_focus(state, Some(toplevel.wl_surface().clone()), serial);
                        }
                    }
                }
            }

            if let Some(pointer) = state.seat.get_pointer() {
                pointer.button(
                    state,
                    &ButtonEvent {
                        button,
                        state: button_state,
                        serial,
                        time: event.time_msec(),
                    },
                );
                pointer.frame(state);
            }
        }
        InputEvent::PointerAxis { event } => {
            let source = event.source();
            let horizontal = event
                .amount(Axis::Horizontal)
                .unwrap_or_else(|| event.amount_v120(Axis::Horizontal).unwrap_or(0.0) * 15.0 / 120.0);
            let vertical = event
                .amount(Axis::Vertical)
                .unwrap_or_else(|| event.amount_v120(Axis::Vertical).unwrap_or(0.0) * 15.0 / 120.0);

            let mut frame = AxisFrame::new(event.time_msec()).source(source);
            if horizontal != 0.0 {
                frame = frame.value(Axis::Horizontal, horizontal);
            }
            if vertical != 0.0 {
                frame = frame.value(Axis::Vertical, vertical);
            }
            if let Some(pointer) = state.seat.get_pointer() {
                pointer.axis(state, frame);
                pointer.frame(state);
            }
        }
        _ => {}
    }
}
