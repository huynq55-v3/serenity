use std::process::Command;

use iced::widget::{button, column, container, text, text_input};
use iced::{Border, Color, Element, Font, Length, Size, Theme};
use serenity_ui::{DEJAVU_SANS, resolve_bin, sysinfo::read_system_snapshot};

#[derive(Debug, Clone)]
enum Message {
    UsernameChanged(String),
    PasswordChanged(String),
    Submit,
}

struct LoginApp {
    username: String,
    password: String,
    kernel: String,
    error: Option<String>,
}

impl Default for LoginApp {
    fn default() -> Self {
        let snap = read_system_snapshot();
        let default_user = if snap.user == "root" {
            "serenity".to_string()
        } else {
            snap.user
        };
        Self {
            username: default_user,
            password: String::new(),
            kernel: snap.kernel,
            error: None,
        }
    }
}

impl LoginApp {
    fn title(&self) -> String {
        "Serenity Linux — Sign In".to_string()
    }

    fn update(&mut self, msg: Message) {
        match msg {
            Message::UsernameChanged(u) => {
                self.username = u;
                self.error = None;
            }
            Message::PasswordChanged(p) => {
                self.password = p;
                self.error = None;
            }
            Message::Submit => {
                let user = self.username.trim();
                if user.is_empty() {
                    self.error = Some("Username cannot be empty.".to_string());
                    return;
                }
                if user == "root" {
                    self.error = Some(
                        "Root desktop login is disabled. Sign in as regular user 'serenity'."
                            .to_string(),
                    );
                    return;
                }

                // Launch the standalone Serenity Desktop Shell and exit the greeter.
                let shell_bin = resolve_bin("serenity-shell");
                match Command::new(&shell_bin)
                    .env("SERENITY_USER", user)
                    .spawn()
                {
                    Ok(_) => std::process::exit(0),
                    Err(e) => {
                        self.error = Some(format!(
                            "Failed to launch {}: {}",
                            shell_bin.display(),
                            e
                        ));
                    }
                }
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let mut card_content = column![
            text("Serenity Linux").size(34),
            text(format!("Linux {}  •  Smithay Wayland", self.kernel)).size(13),
            text("").size(10),
            text("Username").size(13),
            text_input("serenity", &self.username)
                .on_input(Message::UsernameChanged)
                .on_submit(Message::Submit)
                .padding(10),
            text("Password").size(13),
            text_input("Enter password (blank for dev)", &self.password)
                .secure(true)
                .on_input(Message::PasswordChanged)
                .on_submit(Message::Submit)
                .padding(10),
            text("").size(4),
            button(text("Sign In").size(15))
                .on_press(Message::Submit)
                .padding([10, 28]),
        ]
        .spacing(10)
        .width(Length::Fixed(380.0));

        if let Some(err) = &self.error {
            card_content = card_content.push(text(err).size(13));
        }

        let card = container(card_content)
            .padding(32)
            .style(|_theme: &Theme| container::Style {
                background: Some(Color::from_rgba(0.11, 0.13, 0.20, 0.96).into()),
                border: Border {
                    color: Color::from_rgba(0.35, 0.45, 0.65, 0.35),
                    width: 1.0,
                    radius: 16.0.into(),
                },
                ..Default::default()
            });

        container(card)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}

fn main() -> iced::Result {
    iced::application(LoginApp::title, LoginApp::update, LoginApp::view)
        .theme(|_| Theme::TokyoNight)
        .font(DEJAVU_SANS)
        .default_font(Font::with_name("DejaVu Sans"))
        .decorations(false)
        .window_size(Size::new(1920.0, 1080.0))
        .run()
}
