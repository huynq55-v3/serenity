use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::process::Command;

const BLOCKED_IPS_PATH: &str = "/etc/serenity/blocked-ips.conf";
const FW_TABLE_NAME: &str = "serenity_fw";
const MODPROBE: &str = "/sbin/modprobe";

// Netlink & nfnetlink constants (Linux 6.18 UAPI)
const NETLINK_NETFILTER: libc::c_int = 12;
const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP: u16 = 0x0300;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_APPEND: u16 = 0x0800;

const NLA_F_NESTED: u16 = 0x8000;

const NFNETLINK_V0: u8 = 0;
const NFNL_SUBSYS_NFTABLES: u8 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x0010;
const NFNL_MSG_BATCH_END: u16 = 0x0011;

// nf_tables message types
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DESTROYTABLE: u16 = 26;

// Netfilter families, hooks, and verdicts
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

// Transport protocol numbers
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

// nf_tables registers and attribute IDs (verified against Linux 6.18 nf_tables.h)
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;

const NFTA_LIST_ELEM: u16 = 1;

const NFTA_TABLE_NAME: u16 = 1;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;

const NFTA_VERDICT_CODE: u16 = 1;

const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;

const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;

const NFT_META_IIF: u32 = 4;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;

const NFT_CT_STATE: u32 = 0;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;

const NF_CT_STATE_INVALID_BIT: u32 = 1 << 0;
const NF_CT_STATE_ESTABLISHED_BIT: u32 = 1 << 1;
const NF_CT_STATE_RELATED_BIT: u32 = 1 << 2;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

struct NlaBuf {
    buf: Vec<u8>,
}

impl NlaBuf {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn init_nf_msg(msg_type: u16, flags: u16, seq: u32, family: u8, res_id: u16) -> Self {
        let mut msg = Self::new();
        msg.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len placeholder
        msg.buf.extend_from_slice(&msg_type.to_ne_bytes());
        msg.buf.extend_from_slice(&flags.to_ne_bytes());
        msg.buf.extend_from_slice(&seq.to_ne_bytes());
        msg.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        // nfgenmsg
        msg.buf.push(family);
        msg.buf.push(NFNETLINK_V0);
        msg.buf.extend_from_slice(&res_id.to_be_bytes());
        msg
    }

    fn put_attr(&mut self, attr_type: u16, data: &[u8]) {
        let total = 4 + data.len();
        self.buf.extend_from_slice(&(total as u16).to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        let pad = align4(total) - total;
        self.buf.resize(self.buf.len() + pad, 0);
    }

    fn put_str(&mut self, attr_type: u16, s: &str) {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        self.put_attr(attr_type, &bytes);
    }

    fn put_be32(&mut self, attr_type: u16, v: u32) {
        self.put_attr(attr_type, &v.to_be_bytes());
    }

    fn put_nested<F>(&mut self, attr_type: u16, f: F)
    where
        F: FnOnce(&mut NlaBuf),
    {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // nla_len placeholder
        self.buf
            .extend_from_slice(&(attr_type | NLA_F_NESTED).to_ne_bytes());
        f(self);
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn finish_nlmsg(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn nft_msg_type(sub_msg: u16) -> u16 {
    ((NFNL_SUBSYS_NFTABLES as u16) << 8) | sub_msg
}

fn add_expr<F>(list: &mut NlaBuf, name: &str, f: F)
where
    F: FnOnce(&mut NlaBuf),
{
    list.put_nested(NFTA_LIST_ELEM, |elem| {
        elem.put_str(NFTA_EXPR_NAME, name);
        elem.put_nested(NFTA_EXPR_DATA, f);
    });
}

fn expr_meta_eq(list: &mut NlaBuf, key: u32, val: &[u8]) {
    add_expr(list, "meta", |d| {
        d.put_be32(NFTA_META_DREG, NFT_REG_1);
        d.put_be32(NFTA_META_KEY, key);
    });
    add_expr(list, "cmp", |d| {
        d.put_be32(NFTA_CMP_SREG, NFT_REG_1);
        d.put_be32(NFTA_CMP_OP, NFT_CMP_EQ);
        d.put_nested(NFTA_CMP_DATA, |v| {
            v.put_attr(NFTA_DATA_VALUE, val);
        });
    });
}

fn expr_payload_eq(list: &mut NlaBuf, base: u32, offset: u32, len: u32, val: &[u8]) {
    add_expr(list, "payload", |d| {
        d.put_be32(NFTA_PAYLOAD_DREG, NFT_REG_1);
        d.put_be32(NFTA_PAYLOAD_BASE, base);
        d.put_be32(NFTA_PAYLOAD_OFFSET, offset);
        d.put_be32(NFTA_PAYLOAD_LEN, len);
    });
    add_expr(list, "cmp", |d| {
        d.put_be32(NFTA_CMP_SREG, NFT_REG_1);
        d.put_be32(NFTA_CMP_OP, NFT_CMP_EQ);
        d.put_nested(NFTA_CMP_DATA, |v| {
            v.put_attr(NFTA_DATA_VALUE, val);
        });
    });
}

fn expr_ct_state_any(list: &mut NlaBuf, mask: u32) {
    add_expr(list, "ct", |d| {
        d.put_be32(NFTA_CT_DREG, NFT_REG_1);
        d.put_be32(NFTA_CT_KEY, NFT_CT_STATE);
    });
    add_expr(list, "bitwise", |d| {
        d.put_be32(NFTA_BITWISE_SREG, NFT_REG_1);
        d.put_be32(NFTA_BITWISE_DREG, NFT_REG_1);
        d.put_be32(NFTA_BITWISE_LEN, 4);
        d.put_nested(NFTA_BITWISE_MASK, |v| {
            v.put_attr(NFTA_DATA_VALUE, &mask.to_ne_bytes());
        });
        d.put_nested(NFTA_BITWISE_XOR, |v| {
            v.put_attr(NFTA_DATA_VALUE, &[0u8; 4]);
        });
    });
    add_expr(list, "cmp", |d| {
        d.put_be32(NFTA_CMP_SREG, NFT_REG_1);
        d.put_be32(NFTA_CMP_OP, NFT_CMP_NEQ);
        d.put_nested(NFTA_CMP_DATA, |v| {
            v.put_attr(NFTA_DATA_VALUE, &[0u8; 4]);
        });
    });
}

fn expr_verdict(list: &mut NlaBuf, verdict: u32) {
    add_expr(list, "immediate", |d| {
        d.put_be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        d.put_nested(NFTA_IMMEDIATE_DATA, |data| {
            data.put_nested(NFTA_DATA_VERDICT, |v| {
                v.put_be32(NFTA_VERDICT_CODE, verdict);
            });
        });
    });
}

fn msg_destroytable(seq: u32, family: u8, name: &str) -> Vec<u8> {
    let mut msg = NlaBuf::init_nf_msg(nft_msg_type(NFT_MSG_DESTROYTABLE), NLM_F_REQUEST, seq, family, 0);
    msg.put_str(NFTA_TABLE_NAME, name);
    msg.finish_nlmsg()
}

fn msg_newtable(seq: u32, family: u8, name: &str) -> Vec<u8> {
    let mut msg = NlaBuf::init_nf_msg(
        nft_msg_type(NFT_MSG_NEWTABLE),
        NLM_F_REQUEST | NLM_F_CREATE,
        seq,
        family,
        0,
    );
    msg.put_str(NFTA_TABLE_NAME, name);
    msg.finish_nlmsg()
}

fn msg_newchain(seq: u32, family: u8, table: &str, name: &str, hook: u32, policy: u32) -> Vec<u8> {
    let mut msg = NlaBuf::init_nf_msg(
        nft_msg_type(NFT_MSG_NEWCHAIN),
        NLM_F_REQUEST | NLM_F_CREATE,
        seq,
        family,
        0,
    );
    msg.put_str(NFTA_CHAIN_TABLE, table);
    msg.put_str(NFTA_CHAIN_NAME, name);
    msg.put_nested(NFTA_CHAIN_HOOK, |h| {
        h.put_be32(NFTA_HOOK_HOOKNUM, hook);
        h.put_be32(NFTA_HOOK_PRIORITY, 0);
    });
    msg.put_be32(NFTA_CHAIN_POLICY, policy);
    msg.put_str(NFTA_CHAIN_TYPE, "filter");
    msg.finish_nlmsg()
}

fn msg_newrule<F>(seq: u32, family: u8, table: &str, chain: &str, f: F) -> Vec<u8>
where
    F: FnOnce(&mut NlaBuf),
{
    let mut msg = NlaBuf::init_nf_msg(
        nft_msg_type(NFT_MSG_NEWRULE),
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
        seq,
        family,
        0,
    );
    msg.put_str(NFTA_RULE_TABLE, table);
    msg.put_str(NFTA_RULE_CHAIN, chain);
    msg.put_nested(NFTA_RULE_EXPRESSIONS, f);
    msg.finish_nlmsg()
}

pub fn build_default_ruleset_batch(lo_ifindex: u32, blocked_ips: &[Ipv4Addr]) -> Vec<Vec<u8>> {
    let mut msgs = Vec::new();
    // seq=1 is reserved for NFNL_MSG_BATCH_BEGIN; inner messages start at seq=2.
    let mut seq: u32 = 1;
    let mut next_seq = || -> u32 {
        seq += 1;
        seq
    };

    msgs.push(msg_destroytable(next_seq(), NFPROTO_INET, FW_TABLE_NAME));
    msgs.push(msg_newtable(next_seq(), NFPROTO_INET, FW_TABLE_NAME));

    msgs.push(msg_newchain(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "input",
        NF_INET_LOCAL_IN,
        NF_DROP,
    ));
    msgs.push(msg_newchain(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "forward",
        NF_INET_FORWARD,
        NF_DROP,
    ));
    msgs.push(msg_newchain(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "output",
        NF_INET_LOCAL_OUT,
        NF_ACCEPT,
    ));

    // 1. Allow loopback interface (localhost)
    msgs.push(msg_newrule(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "input",
        |exprs| {
            expr_meta_eq(exprs, NFT_META_IIF, &lo_ifindex.to_ne_bytes());
            expr_verdict(exprs, NF_ACCEPT);
        },
    ));

    // 2. Drop blocked IPv4 sources before conntrack state accept
    for &ip in blocked_ips {
        msgs.push(msg_newrule(
            next_seq(),
            NFPROTO_INET,
            FW_TABLE_NAME,
            "input",
            |exprs| {
                expr_meta_eq(exprs, NFT_META_NFPROTO, &[NFPROTO_IPV4]);
                expr_payload_eq(exprs, NFT_PAYLOAD_NETWORK_HEADER, 12, 4, &ip.octets());
                expr_verdict(exprs, NF_DROP);
            },
        ));
    }

    // 3. Drop invalid connection-tracking packets
    msgs.push(msg_newrule(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "input",
        |exprs| {
            expr_ct_state_any(exprs, NF_CT_STATE_INVALID_BIT);
            expr_verdict(exprs, NF_DROP);
        },
    ));

    // 4. Accept established & related inbound replies to our outbound traffic
    msgs.push(msg_newrule(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "input",
        |exprs| {
            expr_ct_state_any(
                exprs,
                NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT,
            );
            expr_verdict(exprs, NF_ACCEPT);
        },
    ));

    // 5-7. Accept essential IPv6 Neighbor Discovery (RA=134, NS=135, NA=136)
    for nd_type in [134u8, 135u8, 136u8] {
        msgs.push(msg_newrule(
            next_seq(),
            NFPROTO_INET,
            FW_TABLE_NAME,
            "input",
            |exprs| {
                expr_meta_eq(exprs, NFT_META_NFPROTO, &[NFPROTO_IPV6]);
                expr_meta_eq(exprs, NFT_META_L4PROTO, &[IPPROTO_ICMPV6]);
                expr_payload_eq(exprs, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 1, &[nd_type]);
                expr_verdict(exprs, NF_ACCEPT);
            },
        ));
    }

    // 8. Accept DHCPv4 replies (UDP sport 67 -> dport 68)
    msgs.push(msg_newrule(
        next_seq(),
        NFPROTO_INET,
        FW_TABLE_NAME,
        "input",
        |exprs| {
            expr_meta_eq(exprs, NFT_META_NFPROTO, &[NFPROTO_IPV4]);
            expr_meta_eq(exprs, NFT_META_L4PROTO, &[IPPROTO_UDP]);
            expr_payload_eq(exprs, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, &[0, 67, 0, 68]);
            expr_verdict(exprs, NF_ACCEPT);
        },
    ));

    // Drop outbound traffic to blocked IPv4 destinations
    for &ip in blocked_ips {
        msgs.push(msg_newrule(
            next_seq(),
            NFPROTO_INET,
            FW_TABLE_NAME,
            "output",
            |exprs| {
                expr_meta_eq(exprs, NFT_META_NFPROTO, &[NFPROTO_IPV4]);
                expr_payload_eq(exprs, NFT_PAYLOAD_NETWORK_HEADER, 16, 4, &ip.octets());
                expr_verdict(exprs, NF_DROP);
            },
        ));
    }

    msgs
}

struct NetlinkSocket {
    fd: libc::c_int,
}

impl NetlinkSocket {
    fn open_netfilter() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } != 0
        {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        Ok(Self { fd })
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn read_nlmsg_header(slice: &[u8]) -> Option<(usize, u16, u32)> {
    if slice.len() < NLMSG_HDRLEN {
        return None;
    }
    let len = u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
    let msg_type = u16::from_ne_bytes([slice[4], slice[5]]);
    let seq = u32::from_ne_bytes([slice[8], slice[9], slice[10], slice[11]]);
    if len < NLMSG_HDRLEN || len > slice.len() {
        return None;
    }
    Some((len, msg_type, seq))
}

fn send_nft_batch(inner_msgs: &[Vec<u8>]) -> io::Result<()> {
    let sock = NetlinkSocket::open_netfilter()?;
    let end_seq = (inner_msgs.len() as u32) + 2;

    let batch_begin = NlaBuf::init_nf_msg(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        NFPROTO_UNSPEC,
        NFNL_SUBSYS_NFTABLES as u16,
    )
    .finish_nlmsg();

    let batch_end = NlaBuf::init_nf_msg(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST | NLM_F_ACK,
        end_seq,
        NFPROTO_UNSPEC,
        NFNL_SUBSYS_NFTABLES as u16,
    )
    .finish_nlmsg();

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(inner_msgs.len() + 2);
    iovs.push(libc::iovec {
        iov_base: batch_begin.as_ptr() as *mut libc::c_void,
        iov_len: batch_begin.len(),
    });
    for m in inner_msgs {
        iovs.push(libc::iovec {
            iov_base: m.as_ptr() as *mut libc::c_void,
            iov_len: m.len(),
        });
    }
    iovs.push(libc::iovec {
        iov_base: batch_end.as_ptr() as *mut libc::c_void,
        iov_len: batch_end.len(),
    });

    let mut kernel_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut kernel_addr as *mut libc::sockaddr_nl as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    msghdr.msg_iov = iovs.as_mut_ptr();
    msghdr.msg_iovlen = iovs.len() as _;

    let sent = unsafe { libc::sendmsg(sock.fd, &msghdr, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut rx_buf = [0u8; 32768];
    loop {
        let n = unsafe {
            libc::recv(
                sock.fd,
                rx_buf.as_mut_ptr() as *mut libc::c_void,
                rx_buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "netlink socket closed before batch ack",
            ));
        }

        let mut off = 0usize;
        let total = n as usize;
        while off + NLMSG_HDRLEN <= total {
            let Some((msg_len, msg_type, msg_seq)) = read_nlmsg_header(&rx_buf[off..total]) else {
                break;
            };
            if msg_type == NLMSG_NOOP {
                off += align4(msg_len);
                continue;
            }
            if msg_type == NLMSG_ERROR && msg_len >= NLMSG_HDRLEN + 4 {
                let err_code = i32::from_ne_bytes([
                    rx_buf[off + 16],
                    rx_buf[off + 17],
                    rx_buf[off + 18],
                    rx_buf[off + 19],
                ]);
                if err_code != 0 {
                    let os_err = io::Error::from_raw_os_error(-err_code);
                    return Err(io::Error::new(
                        os_err.kind(),
                        format!("nftables batch error at seq {}: {}", msg_seq, os_err),
                    ));
                }
                if msg_seq == end_seq {
                    return Ok(());
                }
            }
            off += align4(msg_len);
        }
    }
}

fn dump_nft(sub_msg: u16, family: u8) -> io::Result<Vec<Vec<u8>>> {
    let sock = NetlinkSocket::open_netfilter()?;
    let seq = 1u32;
    let query = NlaBuf::init_nf_msg(
        nft_msg_type(sub_msg),
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        family,
        0,
    )
    .finish_nlmsg();

    let mut kernel_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    let sent = unsafe {
        libc::sendto(
            sock.fd,
            query.as_ptr() as *const libc::c_void,
            query.len(),
            0,
            &kernel_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut out = Vec::new();
    let mut rx_buf = [0u8; 32768];
    loop {
        let n = unsafe {
            libc::recv(
                sock.fd,
                rx_buf.as_mut_ptr() as *mut libc::c_void,
                rx_buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }

        let mut off = 0usize;
        let total = n as usize;
        while off + NLMSG_HDRLEN <= total {
            let Some((msg_len, msg_type, _)) = read_nlmsg_header(&rx_buf[off..total]) else {
                break;
            };
            if msg_type == NLMSG_NOOP {
                off += align4(msg_len);
                continue;
            }
            if msg_type == NLMSG_DONE {
                return Ok(out);
            }
            if msg_type == NLMSG_ERROR && msg_len >= NLMSG_HDRLEN + 4 {
                let err_code = i32::from_ne_bytes([
                    rx_buf[off + 16],
                    rx_buf[off + 17],
                    rx_buf[off + 18],
                    rx_buf[off + 19],
                ]);
                if err_code != 0 {
                    return Err(io::Error::from_raw_os_error(-err_code));
                }
                return Ok(out);
            }
            out.push(rx_buf[off..off + msg_len].to_vec());
            off += align4(msg_len);
        }
    }
    Ok(out)
}

fn ensure_nft_modules() {
    if Path::new(MODPROBE).exists() {
        let _ = Command::new(MODPROBE)
            .args([
                "-a",
                "-q",
                "--",
                "nfnetlink",
                "nf_tables",
                "nf_conntrack",
                "nf_defrag_ipv4",
                "nf_defrag_ipv6",
                "nft_ct",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn loopback_ifindex() -> u32 {
    fs::read_to_string("/sys/class/net/lo/ifindex")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&idx| idx > 0)
        .unwrap_or(1)
}

pub fn parse_blocked_ips(content: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            if !ip.is_loopback() && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

fn load_blocked_ips() -> Vec<Ipv4Addr> {
    match fs::read_to_string(BLOCKED_IPS_PATH) {
        Ok(s) => parse_blocked_ips(&s),
        Err(_) => Vec::new(),
    }
}

fn save_blocked_ips(ips: &[Ipv4Addr]) -> io::Result<()> {
    let path = Path::new(BLOCKED_IPS_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut content = String::from("# Serenity firewall persistent IPv4 blocklist (one IP per line)\n");
    for ip in ips {
        content.push_str(&format!("{}\n", ip));
    }

    let tmp_path = path.with_file_name("blocked-ips.conf.serenity-new");
    let c_tmp = CString::new(tmp_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL in path"))?;

    let fd = unsafe {
        libc::open(
            c_tmp.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o644 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let res = (|| -> io::Result<()> {
        if unsafe { libc::fchown(fd, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(fd, 0o644) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is an owned file descriptor just opened above.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::rename(&tmp_path, path)
}

pub fn apply_default_firewall() -> io::Result<()> {
    ensure_nft_modules();
    let lo_idx = loopback_ifindex();
    let blocked = load_blocked_ips();
    let batch = build_default_ruleset_batch(lo_idx, &blocked);
    send_nft_batch(&batch)
}

#[derive(Debug, PartialEq, Eq)]
struct ChainSummary {
    table: String,
    name: String,
    policy: Option<u32>,
}

fn iter_nlas<'a>(mut payload: &'a [u8]) -> Vec<(u16, &'a [u8])> {
    let mut attrs = Vec::new();
    while payload.len() >= 4 {
        let nla_len = u16::from_ne_bytes([payload[0], payload[1]]) as usize;
        let nla_type = u16::from_ne_bytes([payload[2], payload[3]]) & 0x3fff;
        if nla_len < 4 || nla_len > payload.len() {
            break;
        }
        attrs.push((nla_type, &payload[4..nla_len]));
        let step = align4(nla_len);
        if step >= payload.len() {
            break;
        }
        payload = &payload[step..];
    }
    attrs
}

fn cstr_from_bytes(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..end]).ok().map(str::to_string)
}

fn parse_chain_msg(msg: &[u8]) -> Option<ChainSummary> {
    let hdr_total = NLMSG_HDRLEN + NFGENMSG_LEN;
    if msg.len() < hdr_total {
        return None;
    }
    let mut table = None;
    let mut name = None;
    let mut policy = None;
    for (ty, data) in iter_nlas(&msg[hdr_total..]) {
        match ty {
            NFTA_CHAIN_TABLE => table = cstr_from_bytes(data),
            NFTA_CHAIN_NAME => name = cstr_from_bytes(data),
            NFTA_CHAIN_POLICY if data.len() == 4 => {
                policy = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }
    }
    Some(ChainSummary {
        table: table?,
        name: name?,
        policy,
    })
}

fn parse_rule_table_chain(msg: &[u8]) -> Option<(String, String)> {
    let hdr_total = NLMSG_HDRLEN + NFGENMSG_LEN;
    if msg.len() < hdr_total {
        return None;
    }
    let mut table = None;
    let mut chain = None;
    for (ty, data) in iter_nlas(&msg[hdr_total..]) {
        match ty {
            NFTA_RULE_TABLE => table = cstr_from_bytes(data),
            NFTA_RULE_CHAIN => chain = cstr_from_bytes(data),
            _ => {}
        }
    }
    Some((table?, chain?))
}

fn print_status() -> io::Result<()> {
    let chains_raw = dump_nft(NFT_MSG_GETCHAIN, NFPROTO_INET)?;
    let rules_raw = dump_nft(NFT_MSG_GETRULE, NFPROTO_INET)?;

    let chains: Vec<ChainSummary> = chains_raw
        .iter()
        .filter_map(|m| parse_chain_msg(m))
        .filter(|c| c.table == FW_TABLE_NAME)
        .collect();

    if chains.is_empty() {
        println!(
            "serenity-fw: table '{}' is NOT loaded (run 'sudo serenity-fw reload').",
            FW_TABLE_NAME
        );
    } else {
        println!("serenity-fw: active (table 'inet {}')", FW_TABLE_NAME);
        for chain in &chains {
            let pol_str = match chain.policy {
                Some(NF_DROP) => "DROP",
                Some(NF_ACCEPT) => "ACCEPT",
                Some(_) => "OTHER",
                None => "none",
            };
            let count = rules_raw
                .iter()
                .filter_map(|m| parse_rule_table_chain(m))
                .filter(|(t, c)| t == FW_TABLE_NAME && c == &chain.name)
                .count();
            println!(
                "  chain {:<8} policy={:<6} rules={}",
                chain.name, pol_str, count
            );
        }
    }

    let blocked = load_blocked_ips();
    if blocked.is_empty() {
        println!("  blocked_ips: (none)");
    } else {
        let list: Vec<String> = blocked.iter().map(|ip| ip.to_string()).collect();
        println!("  blocked_ips: {}", list.join(", "));
    }
    Ok(())
}

pub fn run_fw_applet() -> ! {
    // /init is SUID-root; enforce ruid == 0 so non-root users must authenticate via sudo.
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 {
        eprintln!("serenity-fw: must be run as root (use 'sudo serenity-fw ...')");
        std::process::exit(1);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd] if cmd == "status" => {
            if let Err(e) = print_status() {
                eprintln!("serenity-fw: failed to query nftables: {}", e);
                std::process::exit(1);
            }
        }
        [cmd] if cmd == "reload" => {
            if let Err(e) = apply_default_firewall() {
                eprintln!("serenity-fw: failed to apply firewall rules: {}", e);
                std::process::exit(1);
            }
            println!("serenity-fw: reloaded '{}' (input=DROP, forward=DROP, output=ACCEPT).", FW_TABLE_NAME);
        }
        [cmd, ip_str] if cmd == "block" => {
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                eprintln!("serenity-fw: invalid IPv4 address '{}'", ip_str);
                std::process::exit(1);
            };
            if ip.is_loopback() {
                eprintln!("serenity-fw: refusing to block loopback address {}", ip);
                std::process::exit(1);
            }
            let mut ips = load_blocked_ips();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
            if let Err(e) = save_blocked_ips(&ips) {
                eprintln!("serenity-fw: failed to save {}: {}", BLOCKED_IPS_PATH, e);
                std::process::exit(1);
            }
            if let Err(e) = apply_default_firewall() {
                eprintln!("serenity-fw: failed to reload firewall rules: {}", e);
                std::process::exit(1);
            }
            println!("serenity-fw: blocked IPv4 {}.", ip);
        }
        [cmd, ip_str] if cmd == "unblock" => {
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                eprintln!("serenity-fw: invalid IPv4 address '{}'", ip_str);
                std::process::exit(1);
            };
            let mut ips = load_blocked_ips();
            let before = ips.len();
            ips.retain(|&x| x != ip);
            if let Err(e) = save_blocked_ips(&ips) {
                eprintln!("serenity-fw: failed to save {}: {}", BLOCKED_IPS_PATH, e);
                std::process::exit(1);
            }
            if let Err(e) = apply_default_firewall() {
                eprintln!("serenity-fw: failed to reload firewall rules: {}", e);
                std::process::exit(1);
            }
            if ips.len() < before {
                println!("serenity-fw: unblocked IPv4 {}.", ip);
            } else {
                println!("serenity-fw: {} was not in blocklist (rules reloaded).", ip);
            }
        }
        _ => {
            eprintln!("Usage: serenity-fw <status | reload | block <ipv4> | unblock <ipv4>>");
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nla_alignment_and_nesting_encoding() {
        let mut msg = NlaBuf::init_nf_msg(nft_msg_type(NFT_MSG_NEWTABLE), NLM_F_REQUEST, 7, NFPROTO_INET, 0);
        msg.put_nested(NFTA_CHAIN_HOOK, |h| {
            h.put_be32(NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
            h.put_be32(NFTA_HOOK_PRIORITY, 0);
        });
        let bytes = msg.finish_nlmsg();
        let (nl_len, nl_type, nl_seq) = read_nlmsg_header(&bytes).expect("valid nlmsg");
        assert_eq!(nl_len, bytes.len());
        assert_eq!(nl_type, ((10u16) << 8) | NFT_MSG_NEWTABLE);
        assert_eq!(nl_seq, 7);

        let outer = iter_nlas(&bytes[NLMSG_HDRLEN + NFGENMSG_LEN..]);
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].0, NFTA_CHAIN_HOOK);
        let inner = iter_nlas(outer[0].1);
        assert_eq!(inner.len(), 2);
        assert_eq!(inner[0].0, NFTA_HOOK_HOOKNUM);
        assert_eq!(inner[0].1, &1u32.to_be_bytes());
        assert_eq!(inner[1].0, NFTA_HOOK_PRIORITY);
        assert_eq!(inner[1].1, &0u32.to_be_bytes());
    }

    #[test]
    fn build_ruleset_has_expected_chains_and_blocked_ip_rules() {
        let ips = [Ipv4Addr::new(203, 0, 113, 42)];
        let batch = build_default_ruleset_batch(1, &ips);
        // 1 destroytable + 1 newtable + 3 newchains + 7 base input rules + 1 block input + 1 block output
        assert_eq!(batch.len(), 14);

        let types: Vec<u16> = batch
            .iter()
            .map(|m| read_nlmsg_header(m).unwrap().1 & 0x00ff)
            .collect();
        assert_eq!(types[0], NFT_MSG_DESTROYTABLE);
        assert_eq!(types[1], NFT_MSG_NEWTABLE);
        assert_eq!(types[2], NFT_MSG_NEWCHAIN);
        assert_eq!(types[3], NFT_MSG_NEWCHAIN);
        assert_eq!(types[4], NFT_MSG_NEWCHAIN);
        assert!(types[5..].iter().all(|&t| t == NFT_MSG_NEWRULE));

        let c_in = parse_chain_msg(&batch[2]).unwrap();
        let c_fwd = parse_chain_msg(&batch[3]).unwrap();
        let c_out = parse_chain_msg(&batch[4]).unwrap();
        assert_eq!(c_in, ChainSummary { table: "serenity_fw".into(), name: "input".into(), policy: Some(NF_DROP) });
        assert_eq!(c_fwd, ChainSummary { table: "serenity_fw".into(), name: "forward".into(), policy: Some(NF_DROP) });
        assert_eq!(c_out, ChainSummary { table: "serenity_fw".into(), name: "output".into(), policy: Some(NF_ACCEPT) });

        // Last rule targets output chain for blocked IP drop
        let (tbl, ch) = parse_rule_table_chain(batch.last().unwrap()).unwrap();
        assert_eq!(tbl, "serenity_fw");
        assert_eq!(ch, "output");
    }

    #[test]
    fn parse_blocked_ips_filters_loopback_comments_and_dups() {
        let input = "\
# comment
192.0.2.10 # inline comment

127.0.0.1
127.0.1.1
not-an-ip
192.0.2.10
198.51.100.7
";
        let parsed = parse_blocked_ips(input);
        assert_eq!(
            parsed,
            vec![Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(198, 51, 100, 7)]
        );
    }

    #[test]
    fn parse_chain_summary_decodes_drop_and_accept() {
        let drop_msg = msg_newchain(2, NFPROTO_INET, "serenity_fw", "input", NF_INET_LOCAL_IN, NF_DROP);
        let acc_msg = msg_newchain(3, NFPROTO_INET, "serenity_fw", "output", NF_INET_LOCAL_OUT, NF_ACCEPT);
        assert_eq!(parse_chain_msg(&drop_msg).unwrap().policy, Some(NF_DROP));
        assert_eq!(parse_chain_msg(&acc_msg).unwrap().policy, Some(NF_ACCEPT));
    }
}
