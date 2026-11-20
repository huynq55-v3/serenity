mod sysinfo;
mod wifi;

use iced::widget::{
    button, column, container, horizontal_space, row, scrollable, text, text_input,
};
use iced::{Alignment, Element, Length, Size, Theme};

use sysinfo::{SystemSnapshot, read_system_snapshot, run_shell_command};
use wifi::{WifiNetwork, connect_network, detect_wifi_interface, scan_networks};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    Login,
    Desktop,
}

#[derive(Debug, Clone)]
enum Message {
    // Login screen
    UsernameChanged(String),
    PasswordChanged(String),
    LoginSubmit,
    Logout,

    // Wi-Fi manager
    WifiScan,
    WifiSelect(String),
    WifiSsidChanged(String),
    WifiPassChanged(String),
    WifiConnect,

    // Nushell command runner
    CmdInputChanged(String),
    CmdRun,
    CmdQuick(String),
    RefreshSystem,
}

struct SerenityShell {
    screen: Screen,
    username: String,
    password: String,
    login_error: Option<String>,

    sys: SystemSnapshot,
    wifi_iface: Option<String>,
    wifi_networks: Vec<WifiNetwork>,
    wifi_ssid: String,
    wifi_pass: String,
    wifi_status: String,

    cmd_input: String,
    cmd_output: String,
}

impl Default for SerenityShell {
    fn default() -> Self {
        let sys = read_system_snapshot();
        let wifi_iface = detect_wifi_interface();
        let wifi_status = match &wifi_iface {
            Some(dev) => format!("Interface '{}' detected. Click Scan to list networks.", dev),
            None => "No wireless NIC detected (/sys/class/net/*/wireless).".to_string(),
        };

        Self {
            screen: Screen::Login,
            username: sys.user.clone(),
            password: String::new(),
            login_error: None,
            sys,
            wifi_iface,
            wifi_networks: Vec::new(),
            wifi_ssid: String::new(),
            wifi_pass: String::new(),
            wifi_status,
            cmd_input: "uname -a".to_string(),
            cmd_output: "Welcome to Serenity Desktop Shell!\nRun any command below or click a quick action.".to_string(),
        }
    }
}

impl SerenityShell {
    fn title(&self) -> String {
        match self.screen {
            Screen::Login => "Serenity Linux — Sign In".to_string(),
            Screen::Desktop => format!("Serenity Desktop — {}@serenity", self.username),
        }
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::UsernameChanged(u) => {
                self.username = u;
                self.login_error = None;
            }
            Message::PasswordChanged(p) => {
                self.password = p;
                self.login_error = None;
            }
            Message::LoginSubmit => {
                let user = self.username.trim();
                if user.is_empty() {
                    self.login_error = Some("Username cannot be empty.".to_string());
                } else if user == "root" {
                    self.login_error =
                        Some("Root desktop login is disabled. Use a regular user (e.g. serenity).".to_string());
                } else {
                    self.password.clear();
                    self.login_error = None;
                    self.sys = read_system_snapshot();
                    self.screen = Screen::Desktop;
                }
            }
            Message::Logout => {
                self.screen = Screen::Login;
                self.password.clear();
            }
            Message::WifiScan => {
                self.wifi_iface = detect_wifi_interface();
                match scan_networks(self.wifi_iface.as_deref()) {
                    Ok(nets) => {
                        self.wifi_status = format!("Found {} Wi-Fi network(s).", nets.len());
                        self.wifi_networks = nets;
                    }
                    Err(e) => {
                        self.wifi_status = e;
                    }
                }
            }
            Message::WifiSelect(ssid) => {
                self.wifi_ssid = ssid;
                self.wifi_status = format!("Selected '{}'. Enter password and click Connect.", self.wifi_ssid);
            }
            Message::WifiSsidChanged(s) => self.wifi_ssid = s,
            Message::WifiPassChanged(p) => self.wifi_pass = p,
            Message::WifiConnect => {
                match connect_network(self.wifi_iface.as_deref(), &self.wifi_ssid, &self.wifi_pass) {
                    Ok(msg) => {
                        self.wifi_status = msg;
                        self.wifi_pass.clear();
                    }
                    Err(e) => self.wifi_status = format!("Error: {}", e),
                }
            }
            Message::CmdInputChanged(c) => self.cmd_input = c,
            Message::CmdRun => {
                let out = run_shell_command(&self.cmd_input);
                self.cmd_output = format!("$ {}\n{}", self.cmd_input.trim(), out);
                self.sys = read_system_snapshot();
            }
            Message::CmdQuick(cmd) => {
                self.cmd_input = cmd.clone();
                let out = run_shell_command(&cmd);
                self.cmd_output = format!("$ {}\n{}", cmd, out);
                self.sys = read_system_snapshot();
            }
            Message::RefreshSystem => {
                self.sys = read_system_snapshot();
                self.wifi_iface = detect_wifi_interface();
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        match self.screen {
            Screen::Login => self.view_login(),
            Screen::Desktop => self.view_desktop(),
        }
    }

    fn view_login(&self) -> Element<'_, Message> {
        let mut card = column![
            text("Serenity Linux").size(32),
            text("Rust + Linux Kernel + Smithay Wayland").size(14),
            text("").size(8),
            text("Username (non-root)").size(13),
            text_input("serenity", &self.username)
                .on_input(Message::UsernameChanged)
                .on_submit(Message::LoginSubmit)
                .padding(10),
            text("Password").size(13),
            text_input("Leave blank for dev session", &self.password)
                .secure(true)
                .on_input(Message::PasswordChanged)
                .on_submit(Message::LoginSubmit)
                .padding(10),
            button(text("Sign In to Serenity Desktop").size(15))
                .on_press(Message::LoginSubmit)
                .padding([10, 20]),
        ]
        .spacing(10)
        .width(Length::Fixed(380.0));

        if let Some(err) = &self.login_error {
            card = card.push(text(err).size(13));
        }

        container(container(card).padding(28))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn view_desktop(&self) -> Element<'_, Message> {
        let top_bar = row![
            text("Serenity Linux 0.1.0").size(18),
            text(format!("  |  Linux {}", self.sys.kernel)).size(13),
            text(format!("  |  Uptime {}", self.sys.uptime)).size(13),
            horizontal_space(),
            text(format!("User: {}  ", self.username)).size(13),
            button("Refresh").on_press(Message::RefreshSystem).padding([6, 12]),
            button("Sign Out").on_press(Message::Logout).padding([6, 12]),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        // Left panel: Wi-Fi Manager
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

        let wifi_panel = column![
            row![
                text("Wi-Fi Manager").size(20),
                horizontal_space(),
                button("Scan Wi-Fi").on_press(Message::WifiScan).padding([6, 12]),
            ]
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
                .padding([8, 16]),
        ]
        .spacing(10)
        .width(Length::FillPortion(2));

        // Right panel: System + Nushell Command Runner
        let quick_row = row![
            button("spkg list")
                .on_press(Message::CmdQuick("spkg list".into()))
                .padding([6, 10]),
            button("spkg search")
                .on_press(Message::CmdQuick("spkg search".into()))
                .padding([6, 10]),
            button("uname -a")
                .on_press(Message::CmdQuick("uname -a".into()))
                .padding([6, 10]),
            button("ls /")
                .on_press(Message::CmdQuick("ls /".into()))
                .padding([6, 10]),
        ]
        .spacing(8);

        let runner_panel = column![
            row![
                text("Nushell Command Runner").size(20),
                horizontal_space(),
                text(format!("spkg installed: {}", self.sys.installed_pkgs)).size(13),
            ]
            .align_y(Alignment::Center),
            quick_row,
            row![
                text_input("Enter command...", &self.cmd_input)
                    .on_input(Message::CmdInputChanged)
                    .on_submit(Message::CmdRun)
                    .padding(8),
                button("Run").on_press(Message::CmdRun).padding([8, 16]),
            ]
            .spacing(8),
            scrollable(container(text(&self.cmd_output).size(13)).padding(10))
                .height(Length::Fill),
        ]
        .spacing(10)
        .width(Length::FillPortion(3));

        let body = row![wifi_panel, runner_panel].spacing(20).height(Length::Fill);

        container(column![top_bar, body].spacing(18))
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

fn main() -> iced::Result {
    iced::application(SerenityShell::title, SerenityShell::update, SerenityShell::view)
        .theme(|_| Theme::TokyoNight)
        .window_size(Size::new(960.0, 560.0))
        .run()
}
