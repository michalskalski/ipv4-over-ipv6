//! BSD-style PF_ROUTE socket for managing the IPv4 default route
//! through the DS-Lite tunnel.
//!
//! After every write, the kernel writes a reply back to the same
//! socket with the originating pid and seq echoed and `rtm_errno`
//! set. The send/ack loop reads until it finds a reply matching
//! `(pid, seq)`, discarding broadcasts from other actors.
//!
//! See `routing(4P)` and `<net/route.h>`.
use std::{
    cell::Cell,
    ffi::c_void,
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process, ptr,
};

use crate::tunnel::illumos::sys::{
    self, RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTF_GATEWAY, RTF_STATIC, RTF_UP, RTM_ADD, RTM_DELETE,
    RTM_VERSION, rt_msghdr,
};

/// Wire-format message for an IPv4 default route operation
/// (RTM_ADD or RTM_DELETE).
///
/// Field order matches ascending RTA_* bit order, which is how the
/// kernel walks the trailing sockaddrs (DST=0x1, GATEWAY=0x2,
/// NETMASK=0x4). Reordering would silently produce wrong routes.
#[repr(C)]
struct DefaultRouteMsg {
    hdr: sys::rt_msghdr,
    dst: libc::sockaddr_in,
    gw: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

const _: () = assert!(std::mem::size_of::<DefaultRouteMsg>() == 124);
const _: () = assert!(std::mem::size_of::<libc::sockaddr_in>() == 16);

/// Owned handle to an open PF_ROUTE socket.
///
/// Invariants:
/// - `fd` is an open PF_ROUTE / SOCK_RAW / AF_UNSPEC socket for the
///   lifetime of the struct. Closed on drop via `OwnedFd`.
/// - `pid` is `getpid()` snapshotted at construction. The kernel
///   echoes this in `rtm_pid` on replies, used to filter out
///   broadcasts originated by other processes.
/// - `seq` is monotonically increasing across `send_route` calls,
///   wrapping at `i32::MAX`. Combined with `pid`, uniquely identifies
///   outstanding request.
pub struct RouteSocket {
    fd: OwnedFd,
    seq: Cell<i32>,
    pid: i32,
}

impl RouteSocket {
    pub fn open() -> io::Result<Self> {
        // SAFETY: FFI call with no outstanding preconditions.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY:
        // - `raw` was returned by `libc::socket` and is non-negative
        //   (the prior `< 0` check rejects the error case), so it is a
        //   valid open file descriptor.
        // - `raw` was created by the call above and has not been observed
        //   by any other code, so this `from_raw_fd` is the sole owner.
        // - The returned `OwnedFd` will close the descriptor on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };

        // SAFETY: FFI call. `value` points to a live `timeval` valid for the
        // duration of the call. `option_len` matches its size.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let pid = process::id();

        Ok(RouteSocket {
            fd,
            seq: Cell::new(0),
            pid: pid as i32,
        })
    }

    fn next_seq(&self) -> i32 {
        let s = self.seq.get();
        self.seq.set(s.wrapping_add(1));
        s
    }

    fn send_default_route(&self, msg_type: u8, gateway: Ipv4Addr) -> io::Result<()> {
        let msg_len = size_of::<DefaultRouteMsg>();
        let seq = self.next_seq();
        let hdr = rt_msghdr {
            rtm_msglen: msg_len as u16,
            rtm_version: RTM_VERSION,
            rtm_type: msg_type,
            rtm_flags: RTF_UP | RTF_GATEWAY | RTF_STATIC,
            rtm_addrs: RTA_DST | RTA_GATEWAY | RTA_NETMASK,
            rtm_seq: seq,
            ..Default::default()
        };

        let msg = DefaultRouteMsg {
            hdr,
            dst: sys::sockaddr_in_v4(Ipv4Addr::UNSPECIFIED),
            gw: sys::sockaddr_in_v4(gateway),
            mask: sys::sockaddr_in_v4(Ipv4Addr::UNSPECIFIED),
        };

        let msg_ptr = &msg as *const _ as *const c_void;

        // SAFETY: FFI call. `buf` points to a fully-initialized `DefaultRouteMsg`
        // valid for `count` bytes (the struct's size)
        let res = unsafe { libc::write(self.fd.as_raw_fd(), msg_ptr, msg_len) };

        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        if (res as usize) < msg_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to PF_ROUTE",
            ));
        }

        let mut buf = [0u8; 1024];
        loop {
            // SAFETY:: FFI call. Buffer is writable for buf.len() bytes
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if (n as usize) < size_of::<rt_msghdr>() {
                continue;
            }
            // SAFETY: n >= size_of::<rt_msghdr>() checked above.
            // The read_unaligned lifts the aligment requiment
            let hdr: rt_msghdr = unsafe { ptr::read_unaligned(buf.as_ptr() as *const rt_msghdr) };
            if hdr.rtm_pid != self.pid || hdr.rtm_seq != seq {
                continue;
            };
            if hdr.rtm_errno != 0 {
                return Err(io::Error::from_raw_os_error(hdr.rtm_errno));
            };
            return Ok(());
        }
    }

    pub fn add_default_v4(&self, gateway: Ipv4Addr) -> io::Result<()> {
        self.send_default_route(RTM_ADD, gateway)?;
        tracing::debug!("tunnel default route installed");
        Ok(())
    }

    pub fn delete_default_v4(&self, gateway: Ipv4Addr) -> io::Result<()> {
        self.send_default_route(RTM_DELETE, gateway)?;
        tracing::debug!("tunnel default route removed");
        Ok(())
    }
}
