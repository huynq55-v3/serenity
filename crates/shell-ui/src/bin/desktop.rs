use std::process::Command;

use iced::widget::{
    button, column, container, horizontal_space, row, scrollable, text, text_input, vertical_space,
};
use iced::{Alignment, Border, Color, Element, Font, Length, Size, Theme};
use serenity_ui::{
    ROBOTO_REGULAR, resolve_bin,
    sysinfo::{SystemSnapshot, read_system_snapshot},
    wifi::{WifiNetwork, connect_network, detect_wifi_interface, scan_networks},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActivePanel {
    None,
    Wifi,
    System,
}

#[derive(Debug, Clone)]
enum Message {
    // Dock actions
    LaunchTerminal,
    ToggleWifiPanel,
    ToggleSystemPanel,
    SignOut,

    // Wi-Fi panel
    WifiScan,
    WifiSelect(String),
    WifiSsidChanged(String),
    WifiPassChanged(String),
    WifiConnect,

    // System panel
    RefreshSystem,
}

struct DesktopShell {
    user: String,
    sys: SystemSnapshot,
    active_panel: ActivePanel,
    status_toast: String,

    wifi_iface: Option<String>,
    wifi_networks: Vec<WifiNetwork>,
    wifi_ssid: String,
    wifi_pass: String,
    wifi_status: String,
}

impl Default for DesktopShell {
    fn default() -> Self {
        let sys = read_system_snapshot();
        let user = std::env::var("SERENITY_USER").unwrap_or_else(|_| sys.user.clone());
        let wifi_iface = detect_wifi_interface();
        let wifi_status = match &wifi_iface {
            Some(dev) => format!("Wi-Fi interface '{}' ready. Click Scan to search.", dev),
            None => "No wireless NIC detected.".to_string(),
        };

        Self {
            user,
            sys,
            active_panel: ActivePanel::None,
            status_toast: "Serenity Desktop ready — click Terminal on the dock to open Nushell."
                .to_string(),
            wifi_iface,
            wifi_networks: Vec::new(),
            wifi_ssid: String::new(),
            wifi_pass: String::new(),
            wifi_status,
        }
    }
}

impl DesktopShell {
    fn title(&self) -> String {
        format!("Serenity Desktop — {}@serenity", self.user)
    }

    fn update(&mut self, msg: Message) {
        match msg {
            Message::LaunchTerminal => {
                let mut cmd = Command::new("alacritty");
                if std::path::Path::new("/bin/nu").exists() {
                    cmd.args(["-e", "/bin/nu"]);
                }
                match cmd.spawn() {
                    Ok(_) => {
                        self.status_toast = "Opened Alacritty (Nushell).".to_string();
                    }
                    Err(e) => {
                        self.status_toast = format!(
                            "Failed to launch alacritty ({}). Install with: sudo apt install -y alacritty",
                            e
                        );
                    }
                }
            }
            Message::ToggleWifiPanel => {
                self.active_panel = if self.active_panel == ActivePanel::Wifi {
                    ActivePanel::None
                } else {
                    self.wifi_iface = detect_wifi_interface();
                    ActivePanel::Wifi
                };
            }
            Message::ToggleSystemPanel => {
                self.active_panel = if self.active_panel == ActivePanel::System {
                    ActivePanel::None
                } else {
                    self.sys = read_system_snapshot();
                    ActivePanel::System
                };
            }
            Message::SignOut => {
                let login_bin = resolve_bin("serenity-login");
                let _ = Command::new(login_bin).spawn();
                std::process::exit(0);
            }
            Message::WifiScan => {
                self.wifi_iface = detect_wifi_interface();
                match scan_networks(self.wifi_iface.as_deref()) {
                    Ok(nets) => {
                        self.wifi_status = format!("Found {} Wi-Fi network(s).", nets.len());
                        self.wifi_networks = nets;
                    }
                    Err(e) => self.wifi_status = e,
                }
            }
            Message::WifiSelect(ssid) => {
                self.wifi_ssid = ssid;
                self.wifi_status = format!("Selected '{}'. Enter password and Connect.", self.wifi_ssid);
            }
            Message::WifiSsidChanged(s) => self.wifi_ssid = s,
            Message::WifiPassChanged(p) => self.wifi_pass = p,
            Message::WifiConnect => {
                match connect_network(self.wifi_iface.as_deref(), &self.wifi_ssid, &self.wifi_pass) {
                    Ok(msg) => {
                        self.wifi_status = msg.clone();
                        self.status_toast = msg;
                        self.wifi_pass.clear();
                    }
                    Err(e) => self.wifi_status = format!("Error: {}", e),
                }
            }
            Message::RefreshSystem => {
                self.sys = read_system_snapshot();
                self.wifi_iface = detect_wifi_interface();
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        // 1. Sleek Top Menu Bar (macOS-inspired)
        let wifi_badge = match &self.wifi_iface {
            Some(dev) => format!("Wi-Fi: {}", dev),
            None => "Net: wired/offline".to_string(),
        };

        let top_bar = container(
            row![
                text("Serenity").size(15),
                text(format!("  •  Linux {}", self.sys.kernel)).size(13),
                horizontal_space(),
                text(&self.status_toast).size(12),
                horizontal_space(),
                text(format!("{}   |   Uptime {}   |   {}", wifi_badge, self.sys.uptime, self.user))
                    .size(13),
            ]
            .align_y(Alignment::Center),
        )
        .padding([8, 18])
        .width(Length::Fill)
        .style(|_theme: &Theme| container::Style {
            background: Some(Color::from_rgba(0.06, 0.08, 0.13, 0.92).into()),
            border: Border {
                color: Color::from_rgba(1.0, 1.0, 1.0, 0.08),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        });

        // 2. Center Workspace (shows optional floating panel: Wi-Fi or System)
        let center_area: Element<'_, Message> = match self.active_panel {
            ActivePanel::None => container(
                column![
                    text("Serenity Linux 0.1.0").size(36),
                    text("Rust Userland  •  Nushell  •  Smithay Wayland").size(15),
                ]
                .spacing(8)
                .align_x(Alignment::Center),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into(),

            ActivePanel::Wifi => {
                let mut net_list = column![].spacing(6);
                for net in &self.wifi_networks {
                    let label = format!("{}  ({} | {})", net.ssid, net.signal, net.security);
                    net_list = net_list.push(
                        button(text(label).size(13))
                            .width(Length::Fill)
                            .on_press(Message::WifiSelect(net.ssid.clone()))
                            .padding([6, 10]),
                    );
                }

                let panel = container(
                    column![
                        row![
                            text("Wi-Fi Manager").size(20),
                            horizontal_space(),
                            button("Scan").on_press(Message::WifiScan).padding([6, 14]),
                            button("Close").on_press(Message::ToggleWifiPanel).padding([6, 12]),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        text(&self.wifi_status).size(13),
                        scrollable(net_list).height(Length::Fixed(180.0)),
                        text_input("Wi-Fi SSID", &self.wifi_ssid)
                            .on_input(Message::WifiSsidChanged)
                            .padding(8),
                        text_input("WPA2/WPA3 Password", &self.wifi_pass)
                            .secure(true)
                            .on_input(Message::WifiPassChanged)
                            .on_submit(Message::WifiConnect)
                            .padding(8),
                        button("Connect Wi-Fi")
                            .on_press(Message::WifiConnect)
                            .padding([8, 18]),
                    ]
                    .spacing(10)
                    .width(Length::Fixed(460.0)),
                )
                .padding(24)
                .style(|_theme: &Theme| container::Style {
                    background: Some(Color::from_rgba(0.11, 0.13, 0.20, 0.96).into()),
                    border: Border {
                        color: Color::from_rgba(0.35, 0.55, 0.85, 0.4),
                        width: 1.0,
                        radius: 16.0.into(),
                    },
                    ..Default::default()
                });

                container(panel)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .into()
            }

            ActivePanel::System => {
                let panel = container(
                    column![
                        row![
                            text("Serenity System Info").size(20),
                            horizontal_space(),
                            button("Refresh").on_press(Message::RefreshSystem).padding([6, 12]),
                            button("Close").on_press(Message::ToggleSystemPanel).padding([6, 12]),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        text(format!("OS       : Serenity Linux 0.1.0 (x86_64-musl)")).size(14),
                        text(format!("Kernel   : Linux {}", self.sys.kernel)).size(14),
                        text(format!("Uptime   : {}", self.sys.uptime)).size(14),
                        text(format!("User     : {} (non-root desktop)", self.user)).size(14),
                        text(format!("spkg     : {} package(s) installed", self.sys.installed_pkgs)).size(14),
                        text(format!("Wi-Fi    : {}", wifi_badge)).size(14),
                    ]
                    .spacing(10)
                    .width(Length::Fixed(440.0)),
                )
                .padding(24)
                .style(|_theme: &Theme| container::Style {
                    background: Some(Color::from_rgba(0.11, 0.13, 0.20, 0.96).into()),
                    border: Border {
                        color: Color::from_rgba(0.35, 0.55, 0.85, 0.4),
                        width: 1.0,
                        radius: 16.0.into(),
                    },
                    ..Default::default()
                });

                container(panel)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .into()
            }
        };

        // 3. macOS-style Floating Pill Dock at the Bottom
        let dock_pill = container(
            row![
                button(text("  Terminal (nu)  ").size(14))
                    .on_press(Message::LaunchTerminal)
                    .padding([12, 16]),
                button(text("  Wi-Fi  ").size(14))
                    .on_press(Message::ToggleWifiPanel)
                    .padding([12, 16]),
                button(text("  System  ").size(14))
                    .on_press(Message::ToggleSystemPanel)
                    .padding([12, 16]),
                button(text("  Sign Out  ").size(14))
                    .on_press(Message::SignOut)
                    .padding([12, 16]),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        )
        .padding([10, 18])
        .style(|_theme: &Theme| container::Style {
            background: Some(Color::from_rgba(0.12, 0.15, 0.23, 0.90).into()),
            border: Border {
                color: Color::from_rgba(0.55, 0.68, 0.92, 0.35),
                width: 1.0,
                radius: 22.0.into(),
            },
            ..Default::default()
        });

        let dock_bar = container(dock_pill)
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(iced::Padding {
                bottom: 18.0,
                ..Default::default()
            });

        column![top_bar, center_area, vertical_space().height(Length::Fixed(4.0)), dock_bar]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

fn main() -> iced::Result {
    iced::application(DesktopShell::title, DesktopShell::update, DesktopShell::view)
        .theme(|_| Theme::TokyoNight)
        .font(ROBOTO_REGULAR)
        .default_font(Font::with_name("Roboto"))
        .decorations(false)
        .window_size(Size::new(1920.0, 1080.0))
        .run()
}
