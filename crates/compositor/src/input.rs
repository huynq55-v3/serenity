use smithay::{
    backend::input::{
        AbsolutePositionEvent, Axis, ButtonState, Event, InputBackend, InputEvent,
        KeyboardKeyEvent, PointerAxisEvent, PointerButtonEvent, PointerMotionEvent,
    },
    input::{
        keyboard::{FilterResult, Keysym},
        pointer::{AxisFrame, ButtonEvent, MotionEvent},
    },
    output::Output,
    utils::SERIAL_COUNTER,
};

use crate::state::SerenityState;

pub fn handle_input<I: InputBackend>(
    state: &mut SerenityState,
    event: InputEvent<I>,
    output: &Output,
) {
    match event {
        InputEvent::Keyboard { event } => {
            let serial = SERIAL_COUNTER.next_serial();
            let time = Event::time_msec(&event);
            let mut should_quit = false;

            if let Some(keyboard) = state.seat.get_keyboard() {
                keyboard.input::<(), _>(
                    state,
                    event.key_code(),
                    event.state(),
                    serial,
                    time,
                    |_, mods, handle| {
                        // Ctrl+Alt+Backspace exits the compositor cleanly back to TTY.
                        if mods.ctrl && mods.alt && handle.modified_sym() == Keysym::BackSpace {
                            should_quit = true;
                            return FilterResult::Intercept(());
                        }
                        FilterResult::Forward
                    },
                );
            }

            if should_quit {
                state.loop_signal.stop();
            }
        }
        InputEvent::PointerMotion { event } => {
            let delta = event.delta();
            let output_geo = state.space.output_geometry(output).unwrap_or_default();
            let max_x = (output_geo.size.w.max(1) - 1) as f64;
            let max_y = (output_geo.size.h.max(1) - 1) as f64;

            state.pointer_location.x = (state.pointer_location.x + delta.x).clamp(0.0, max_x);
            state.pointer_location.y = (state.pointer_location.y + delta.y).clamp(0.0, max_y);

            let pos = state.pointer_location;
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
                let under = state
                    .space
                    .element_under(state.pointer_location)
                    .map(|(w, _)| w.clone());
                if let Some(window) = under {
                    // Keep the base desktop shell (first mapped element) below floating app windows
                    // so clicking the macOS Dock never hides an open Alacritty terminal.
                    let is_base_desktop = state
                        .space
                        .elements()
                        .next()
                        .is_some_and(|first| first == &window)
                        && state.space.elements().count() > 1;
                    if !is_base_desktop {
                        state.space.raise_element(&window, true);
                    }
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
            let horizontal = event.amount(Axis::Horizontal).unwrap_or_else(|| {
                event.amount_v120(Axis::Horizontal).unwrap_or(0.0) * 15.0 / 120.0
            });
            let vertical = event.amount(Axis::Vertical).unwrap_or_else(|| {
                event.amount_v120(Axis::Vertical).unwrap_or(0.0) * 15.0 / 120.0
            });

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
