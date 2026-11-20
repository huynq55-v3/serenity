use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::net::Ipv4Addr;

// Linux ioctl constants for IPv4 interface and route configuration (x86_64).
const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
const SIOCSIFFLAGS: libc::Ioctl = 0x8914;
const SIOCSIFADDR: libc::Ioctl = 0x8916;
const SIOCSIFNETMASK: libc::Ioctl = 0x891c;
const SIOCADDRT: libc::Ioctl = 0x890b;

const RTF_UP: libc::c_ushort = 0x0001;
const RTF_GATEWAY: libc::c_ushort = 0x0002;

#[repr(C)]
struct IfReqAddr {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_addr: libc::sockaddr,
}

#[repr(C)]
struct IfReqFlags {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

#[repr(C)]
struct RtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_ushort,
    rt_pad2: libc::c_short,
    rt_pad3: libc::c_ulong,
    rt_pad4: *mut libc::c_void,
    rt_metric: libc::c_short,
    rt_dev: *mut libc::c_char,
    rt_mtu: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

fn make_sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr {
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    unsafe { mem::transmute_copy(&sa) }
}

fn copy_ifname(name: &str) -> [libc::c_char; libc::IFNAMSIZ] {
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    for (i, b) in name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
        buf[i] = b as libc::c_char;
    }
    buf
}

fn set_ipv4_ioctl(sock: libc::c_int, iface: &str, req: libc::Ioctl, ip: Ipv4Addr) -> io::Result<()> {
    let ifr = IfReqAddr {
        ifr_name: copy_ifname(iface),
        ifr_addr: make_sockaddr_in(ip),
    };
    let rc = unsafe { libc::ioctl(sock, req, &ifr) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn bring_interface_up(sock: libc::c_int, iface: &str) -> io::Result<()> {
    let mut ifr: IfReqFlags = unsafe { mem::zeroed() };
    ifr.ifr_name = copy_ifname(iface);
    if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    ifr.ifr_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn add_default_route(sock: libc::c_int, iface: &str, gateway: Ipv4Addr) -> io::Result<()> {
    let c_iface = CString::new(iface).expect("valid iface name");
    let mut rt: RtEntry = unsafe { mem::zeroed() };
    rt.rt_dst = make_sockaddr_in(Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = make_sockaddr_in(Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = make_sockaddr_in(gateway);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_dev = c_iface.as_ptr() as *mut libc::c_char;

    let rc = unsafe { libc::ioctl(sock, SIOCADDRT, &rt) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        Err(err)
    } else {
        Ok(())
    }
}

fn find_primary_nic() -> Option<String> {
    let entries = fs::read_dir("/sys/class/net").ok()?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "lo")
        .collect();
    names.sort();
    names.into_iter().next()
}

/// Configures loopback (`lo`) and brings up the primary NIC with QEMU SLIRP static IPv4
/// (`10.0.2.15/24`, gateway `10.0.2.2`) so HTTPS/DNS work immediately without an external DHCP client.
pub fn setup_network() -> Option<String> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        eprintln!("[init] warn: network socket failed: {}", io::Error::last_os_error());
        return None;
    }

    // 1. Bring up loopback
    let _ = set_ipv4_ioctl(sock, "lo", SIOCSIFADDR, Ipv4Addr::new(127, 0, 0, 1));
    let _ = set_ipv4_ioctl(sock, "lo", SIOCSIFNETMASK, Ipv4Addr::new(255, 0, 0, 0));
    let _ = bring_interface_up(sock, "lo");

    // 2. Configure primary NIC (e.g. eth0 / ens3)
    let result = if let Some(nic) = find_primary_nic() {
        let ip = Ipv4Addr::new(10, 0, 2, 15);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let gw = Ipv4Addr::new(10, 0, 2, 2);

        let res = set_ipv4_ioctl(sock, &nic, SIOCSIFADDR, ip)
            .and_then(|_| set_ipv4_ioctl(sock, &nic, SIOCSIFNETMASK, mask))
            .and_then(|_| bring_interface_up(sock, &nic))
            .and_then(|_| add_default_route(sock, &nic, gw));

        match res {
            Ok(()) => Some(format!("{} (10.0.2.15/24 via 10.0.2.2)", nic)),
            Err(e) => {
                eprintln!("[init] warn: failed to configure {}: {}", nic, e);
                None
            }
        }
    } else {
        None
    };

    unsafe { libc::close(sock) };
    result
}
