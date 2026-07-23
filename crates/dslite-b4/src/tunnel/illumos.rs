//! illumos backend, DS-Lite B4 tunnel via libdladm + libipadm + direct ioctls.
//!
//! Three layers of the illumos networking stack are used here:
//! - libdladm: datalink/tunnel management (the iptun link itself).
//! - libipadm: IP interface lifecycle (create/delete the IP interface
//!   on top of the link).
//! - kernel ioctls on a socket: IPv4 address assignment. Bypass
//!   libipadm here because of illumos issue 17851, 32-bit `ipmgmtd`
//!   ABI vs this 64-bit daemon.
//!
//! C-side bindings (constants, FFI, `repr(C)` mirrors) live in `sys.rs`.

mod pf_route;
mod sys;

use crate::tunnel::illumos::pf_route::RouteSocket;
use crate::tunnel::{
    AFTR_V4_ELEMENT, B4_V4_PREFIX_LEN, DesiredState, Observed, TunnelBackend, TunnelError,
    TunnelUpdate,
};
use std::io;
use std::mem::MaybeUninit;
use std::{
    ffi::{CString, c_char, c_void},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use sys::*;

pub(crate) use sys::{
    RTM_ADD, RTM_CHGADDR, RTM_DELADDR, RTM_DELETE, RTM_FREEADDR, RTM_NEWADDR, rt_msghdr,
};

// /29 -> 255.255.255.248
const B4_V4_NETMASK: Ipv4Addr = Ipv4Addr::from_bits(u32::MAX << (32 - B4_V4_PREFIX_LEN));

pub struct IllumosBackend {
    cname: CString,
}

impl IllumosBackend {
    pub fn new(name: String) -> Result<Self, std::ffi::NulError> {
        let cname = std::ffi::CString::new(name)?;

        Ok(Self { cname })
    }
    fn create_tunnel(
        &self,
        handle: &DladmHandle,
        desired: &DesiredState,
    ) -> Result<u32, TunnelError> {
        let mut params = build_tunnel_params(&desired.local_v6, &desired.remote_v6);

        // SAFETY:
        // - `handle.ptr` was produced by a successful `dladm_open` (see
        //   `open_dladm`) and remains live for the `&DladmHandle` borrow.
        // - `self.cname.as_ptr()` returns a NUL-terminated `*const c_char`
        //   from the `CString` field, valid for reads for the `&self`
        //   borrow.
        // - `&mut params` is a stack-local `IpTunParams` owned exclusively
        //   here, valid for writes (libdladm populates `link_id`).
        let status = unsafe {
            dladm_iptun_create(
                handle.ptr,
                self.cname.as_ptr(),
                &mut params,
                DLADM_OPT_ACTIVE,
            )
        };
        if status != DLADM_STATUS_OK {
            return Err(TunnelError::CreationFailed(format!(
                "dladm_iptun_create failed with status {}",
                status
            )));
        }
        tracing::debug!(link_id = params.link_id, "tunnel created");

        Ok(params.link_id)
    }

    fn create_if(&self, handle: &IpadmHandle) -> Result<(), TunnelError> {
        // libipadm may write back the canonical interface name into the
        // buffer on success. The writeback happens unconditionally in
        // `i_ipadm_plumb_if` (for the IPv6-type tunnel used here it is
        // normally a no-op, but the API contract requires a writable
        // LIFNAMSIZ buffer).
        // <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libipadm/common/ipadm_if.c#L1105>
        // Allocate a local buffer rather than aliasing the immutable
        // `self.cname` storage. The post-call buffer contents are not
        // read back.
        let src = self.cname.as_bytes_with_nul();
        if src.len() > LIFNAMSIZ {
            return Err(TunnelError::CreationFailed(format!(
                "interface name {} bytes, exceeds LIFNAMSIZ ({})",
                src.len(),
                LIFNAMSIZ
            )));
        }
        let mut name_buf: [c_char; LIFNAMSIZ] = [0; LIFNAMSIZ];

        // SAFETY:
        // - `src` from `as_bytes_with_nul()` is a `&[u8]`, valid for
        //   reads of `src.len()` bytes by the slice-reference guarantee.
        // - `name_buf` is a stack-local `[c_char; LIFNAMSIZ]`, valid for
        //   LIFNAMSIZ writes.
        // - `src.len() <= LIFNAMSIZ` by the prior bounds check.
        // - Both pointers are `u8`-typed. `align_of::<u8>() = 1`, satisfied.
        // - `self.cname` and `name_buf` are distinct allocations, so the
        //   regions cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                name_buf.as_mut_ptr().cast::<u8>(),
                src.len(),
            )
        };

        // SAFETY:
        // - `handle.ptr` was produced by a successful `ipadm_open` (see
        //   `open_ipadm`) and remains live for the `&IpadmHandle` borrow.
        // - `name_buf.as_mut_ptr()` points to an initialized LIFNAMSIZ
        //   buffer that the library may overwrite on success.
        // - `name_buf` lives until function return, covering the call
        //   duration.
        let status = unsafe {
            ipadm_create_if(handle.ptr, name_buf.as_mut_ptr(), AF_INET, IPADM_OPT_ACTIVE)
        };
        if status != IPADM_STATUS_OK {
            return Err(TunnelError::CreationFailed(format!(
                "ipadm_create_if failed with status {}",
                status
            )));
        }
        tracing::debug!("ip interface assigned to tunel");
        Ok(())
    }

    fn get_tunnel_params(&self, handle: &DladmHandle) -> Result<Option<IpTunParams>, TunnelError> {
        let (link_id, status) = self.name_to_linkid(handle);
        if status == DLADM_STATUS_NOTFOUND {
            return Ok(None);
        }
        if status != DLADM_STATUS_OK {
            return Err(TunnelError::StatusCheckFailed(format!(
                "failed to get linkid, dladm_name2info status: {}",
                status
            )));
        }

        // SAFETY: Every field of `IpTunParams` accepts an all-zero bit pattern.
        // Integer fields and byte arrays permit zero, and `IpTunType` is a `u32`
        // alias rather than a restricted Rust enum.
        let mut params: IpTunParams = unsafe { MaybeUninit::zeroed().assume_init() };
        params.link_id = link_id;

        // SAFETY:
        // - `handle.ptr` was produced by a successful `dladm_open` (see
        //   `open_dladm`) and remains live for the `&DladmHandle` borrow.
        // - `&mut params` is a stack-local `IpTunParams` owned exclusively
        //   here, valid for writes.
        let status = unsafe { dladm_iptun_getparams(handle.ptr, &mut params, DLADM_OPT_ACTIVE) };
        if status != DLADM_STATUS_OK {
            return Err(TunnelError::StatusCheckFailed(format!(
                "dladm_iptun_getparams failed with status: {}",
                status
            )));
        };
        Ok(Some(params))
    }

    fn is_admin_up(&self) -> Result<bool, TunnelError> {
        let socket = open_inet_dgram_socket().map_err(|e| {
            TunnelError::StatusCheckFailed(format!("opening interface flags socket: {e}"))
        })?;
        let fd = socket.as_raw_fd();

        // SAFETY: `fd` belongs to the live AF_INET/SOCK_DGRAM `socket`,
        // which accepts SIOCSLIF* ioctls.
        unsafe { is_up(fd, &self.cname) }
            .map_err(|e| TunnelError::StatusCheckFailed(format!("reading interface flags: {e}")))
    }

    fn get_mtu(&self) -> Result<u32, TunnelError> {
        let socket = open_inet_dgram_socket().map_err(|e| {
            TunnelError::StatusCheckFailed(format!("opening interface MTU socket: {e}"))
        })?;
        let fd = socket.as_raw_fd();

        // SAFETY: `fd` belongs to the live AF_INET/SOCK_DGRAM `socket`,
        // which accepts SIOCSLIF* ioctls.
        unsafe { sys::get_mtu(fd, &self.cname) }
            .map_err(|e| TunnelError::StatusCheckFailed(format!("reading interface MTU: {e}")))
    }

    fn delete_tunnel(&self, handle: &DladmHandle) -> Result<(), TunnelError> {
        let (link_id, status) = self.name_to_linkid(handle);
        if status != DLADM_STATUS_OK {
            return Err(TunnelError::DestroyFailed(format!(
                "failed to get linkid, dladm_name2info status: {}",
                status
            )));
        }
        tracing::debug!(link_id, "resolved link id for deletion");

        // SAFETY:
        // - `handle.ptr` was produced by a successful `dladm_open` (see
        //   `open_dladm`) and remains live for the `&DladmHandle` borrow.
        // - `link_id` is a `u32` returned by `dladm_name2info` above,
        //   identifying the link to delete.
        let status = unsafe { dladm_iptun_delete(handle.ptr, link_id, DLADM_OPT_ACTIVE) };
        if status != DLADM_STATUS_OK {
            return Err(TunnelError::DestroyFailed(format!(
                "dladm_iptun_delete failed with status {}",
                status
            )));
        }

        Ok(())
    }

    fn delete_if(&self, handle: &IpadmHandle) -> Result<(), TunnelError> {
        // SAFETY:
        // - `handle.ptr` was produced by a successful `ipadm_open` (see
        //   `open_ipadm`) and remains live for the `&IpadmHandle` borrow.
        // - `self.cname.as_ptr()` returns a NUL-terminated `*const c_char`
        //   from the `CString` field, valid for reads for the `&self`
        //   borrow. `ipadm_delete_if` declares its name parameter `const`
        //   and does not mutate the buffer.
        let status =
            unsafe { ipadm_delete_if(handle.ptr, self.cname.as_ptr(), AF_INET, IPADM_OPT_ACTIVE) };
        if status != IPADM_STATUS_OK {
            return Err(TunnelError::DestroyFailed(format!(
                "ipadm_delete_if failed with status {}",
                status
            )));
        }
        tracing::debug!("ip interface deleted");
        Ok(())
    }

    fn name_to_linkid(&self, handle: &DladmHandle) -> (u32, u32) {
        let mut link_id: u32 = 0;

        // SAFETY:
        // - `handle.ptr` was produced by a successful `dladm_open` (see
        //   `open_dladm`) and remains live for the `&DladmHandle` borrow.
        // - `self.cname.as_ptr()` returns a NUL-terminated `*const c_char`,
        //   valid for reads for the `&self` borrow.
        // - `&mut link_id` points to a stack-local `u32` valid for writes.
        // - The remaining `flagp` / `classp` / `mediap` arguments are
        //   explicitly null. `dladm_name2info` checks each out-pointer
        //   against NULL before writing.
        //   <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdlmgmt.c#L578>
        let status = unsafe {
            dladm_name2info(
                handle.ptr,
                self.cname.as_ptr(),
                &mut link_id,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (link_id, status)
    }
}

impl TunnelBackend for IllumosBackend {
    async fn setup(&self, desired: DesiredState) -> Result<(), TunnelError> {
        let handle = open_dladm().map_err(|e| {
            TunnelError::CreationFailed(format!("unable to open handle, dladm_open status {}", e))
        })?;
        let _link_id = self.create_tunnel(&handle, &desired)?;

        let ip_handle = open_ipadm().map_err(|e| {
            TunnelError::CreationFailed(format!("unable to open handle, ipadm_open status {}", e))
        })?;
        self.create_if(&ip_handle)?;

        let sock_fd = open_inet_dgram_socket().map_err(|e| {
            TunnelError::CreationFailed(format!("opening address configuration socket: {e}"))
        })?;
        let fd = sock_fd.as_raw_fd();

        // The calls below each require an fd that accepts SIOCSLIF* ioctls.
        // `open_inet_dgram_socket` returns an AF_INET/SOCK_DGRAM socket.
        // `sock_fd` (the `OwnedFd`) lives until function return,
        // so `fd` remains valid across all calls.

        if let Some(mtu) = desired.mtu {
            // SAFETY: `fd` is a valid SIOCSLIF*-capable socket (see above).
            unsafe { set_mtu(fd, &self.cname, mtu) }
                .map_err(|e| TunnelError::CreationFailed(format!("set_mtu: {e}")))?;
        }

        // SAFETY: `fd` is a valid SIOCSLIF*-capable socket (see above).
        unsafe { set_local_addr(fd, &self.cname, desired.local_v4) }
            .map_err(|e| TunnelError::CreationFailed(format!("set_local_addr: {}", e)))?;
        // SAFETY: `fd` is a valid SIOCSLIF*-capable socket (see above).
        unsafe { set_dst_addr(fd, &self.cname, AFTR_V4_ELEMENT) }
            .map_err(|e| TunnelError::CreationFailed(format!("set_dst_addr: {}", e)))?;
        // SAFETY: `fd` is a valid SIOCSLIF*-capable socket (see above).
        unsafe { set_netmask(fd, &self.cname, B4_V4_NETMASK) }
            .map_err(|e| TunnelError::CreationFailed(format!("set_netmask: {}", e)))?;
        // SAFETY: `fd` is a valid SIOCSLIF*-capable socket (see above).
        unsafe { bring_up(fd, &self.cname) }
            .map_err(|e| TunnelError::CreationFailed(format!("bring_up: {}", e)))?;
        let route_sock = RouteSocket::open()
            .map_err(|e| TunnelError::CreationFailed(format!("PF_ROUTE open: {e}")))?;
        route_sock
            .add_default_v4(AFTR_V4_ELEMENT)
            .map_err(|e| TunnelError::CreationFailed(format!("add default route: {e}")))?;

        tracing::info!(
            name = %self.cname.to_string_lossy(),
            local_v6 = %desired.local_v6,
            remote_v6 = %desired.remote_v6,
            local_v4 = %desired.local_v4,
            mtu = ?desired.mtu,
            "tunnel established"
        );

        Ok(())
    }

    async fn update(&self, update: TunnelUpdate) -> Result<(), TunnelError> {
        let socket = open_inet_dgram_socket().map_err(|e| {
            TunnelError::UpdateFailed(format!("opening interface configuration socket: {e}"))
        })?;
        let fd = socket.as_raw_fd();

        if let Some(mtu) = update.mtu {
            // SAFETY: `fd` belongs to the live AF_INET/SOCK_DGRAM `socket`,
            // which accepts SIOCSLIF* ioctls.
            unsafe { sys::set_mtu(fd, &self.cname, mtu) }
                .map_err(|e| TunnelError::UpdateFailed(format!("setting interface MTU: {e}")))?;
        }

        if update.bring_up {
            // SAFETY: `fd` belongs to the live AF_INET/SOCK_DGRAM `socket`,
            // which accepts SIOCSLIF* ioctls.
            unsafe { sys::bring_up(fd, &self.cname) }
                .map_err(|e| TunnelError::UpdateFailed(format!("setting interface flags: {e}")))?;
        }

        tracing::info!(
            name = %self.cname.to_string_lossy(),
            mtu = ?update.mtu,
            bring_up = update.bring_up,
            "interface updated"
        );

        Ok(())
    }

    async fn teardown(&self) -> Result<(), TunnelError> {
        let ip_handle = open_ipadm().map_err(|e| {
            TunnelError::DestroyFailed(format!("unable to open handle, ipadm_open status {}", e))
        })?;

        // clear the address
        let sock_fd = open_inet_dgram_socket().map_err(|e| {
            TunnelError::DestroyFailed(format!("opening address configuration socket: {e}"))
        })?;
        let fd = sock_fd.as_raw_fd();

        // SAFETY: `fd` is a fresh AF_INET/SOCK_DGRAM socket from
        // `open_inet_dgram_socket`, which is suitable for SIOCSLIF*.
        // `sock_fd` lives until function return.
        unsafe { set_local_addr(fd, &self.cname, Ipv4Addr::UNSPECIFIED) }
            .map_err(|e| TunnelError::DestroyFailed(format!("zero local_v4: {}", e)))?;

        let route_sock = RouteSocket::open()
            .map_err(|e| TunnelError::DestroyFailed(format!("PF_ROUTE open: {e}")))?;
        if let Err(e) = route_sock.delete_default_v4(AFTR_V4_ELEMENT) {
            if e.raw_os_error() == Some(libc::ESRCH) {
                tracing::warn!(error = %e, "default route already gone");
            } else {
                return Err(TunnelError::DestroyFailed(format!(
                    "delete default route: {e}"
                )));
            }
        }

        self.delete_if(&ip_handle)?;

        let handle = open_dladm().map_err(|e| {
            TunnelError::DestroyFailed(format!("unable to open handle, dladm_open status {}", e))
        })?;
        self.delete_tunnel(&handle)?;

        tracing::info!(
            name = %self.cname.to_string_lossy(),
            "tunnel removed"
        );

        Ok(())
    }

    async fn observe(&self) -> Result<Observed, TunnelError> {
        let handle = open_dladm().map_err(|e| {
            TunnelError::StatusCheckFailed(format!(
                "unable to open handle, dladm_open status {}",
                e
            ))
        })?;

        let Some(params) = self.get_tunnel_params(&handle)? else {
            return Ok(Observed::Absent);
        };

        if params.ip_tun_type != IPTUN_TYPE_IPV6 {
            return Err(TunnelError::StatusCheckFailed(format!(
                "expected IPv6 tunnel type, got {}",
                params.ip_tun_type
            )));
        }

        if params.flags & IPTUN_PARAM_LADDR == 0 {
            return Err(TunnelError::StatusCheckFailed(
                "tunnel local endpoint missing".to_string(),
            ));
        }

        if params.flags & IPTUN_PARAM_RADDR == 0 {
            return Err(TunnelError::StatusCheckFailed(
                "tunnel remote endpoint missing".to_string(),
            ));
        }
        let local_v6 = parse_tunnel_addr(&params.l_addr, "local")?;
        let remote_v6 = parse_tunnel_addr(&params.r_addr, "remote")?;
        let admin_up = self.is_admin_up()?;
        let mtu = self.get_mtu()?;

        Ok(Observed::Present {
            local_v6,
            remote_v6,
            mtu,
            admin_up,
        })
    }
}

/// RAII wrapper for a libdladm handle.
///
/// # Invariants
///
/// - `ptr` is non-null and points to a libdladm handle obtained from a
///   successful `dladm_open`. libdladm only returns `DLADM_STATUS_OK`
///   after writing a non-null, malloc-allocated handle into `*handle`.
///   <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdladm.c#L127-L136>
/// - The handle is exclusively owned by this instance and closed
///   exactly once via `dladm_close` on `Drop`.
///
/// # Threading
///
/// `!Send` and `!Sync` (raw pointer field). libdladm caches a per-handle
/// `door_fd` that is opened on demand and not safe to share across
/// threads. Use a per-thread handle if cross-thread access is needed.
struct DladmHandle {
    ptr: *mut c_void,
}

impl Drop for DladmHandle {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.ptr` is a live libdladm handle (struct invariant).
        // - `dladm_close` is the matching destructor for `dladm_open`.
        // - `Drop::drop` runs exactly once per instance, so the handle
        //   is closed exactly once.
        unsafe { dladm_close(self.ptr) };
    }
}

/// RAII wrapper for a libipadm handle.
///
/// # Invariants
///
/// - `ptr` is non-null and points to a libipadm handle obtained from a
///   successful `ipadm_open`. libipadm sets `*handle` to NULL up front
///   and only assigns a non-null calloc-allocated handle on the success
///   path that returns `IPADM_SUCCESS`.
///   <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libipadm/common/libipadm.c#L181-L264>
/// - The handle is exclusively owned by this instance and closed
///   exactly once via `ipadm_close` on `Drop`.
///
/// # Threading
///
/// `!Send` and `!Sync` (raw pointer field). libipadm holds an internal
/// mutex but also caches sockets and a door fd per handle. Treat the
/// handle as single-thread-owned. Use a per-thread handle if cross-thread
/// access is needed.
struct IpadmHandle {
    ptr: *mut c_void,
}

impl Drop for IpadmHandle {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.ptr` is a live libipadm handle (struct invariant).
        // - `ipadm_close` is the matching destructor for `ipadm_open`.
        // - `Drop::drop` runs exactly once per instance, so the handle
        //   is closed exactly once.
        unsafe { ipadm_close(self.ptr) };
    }
}

fn addr_to_caddr(addr: &std::net::IpAddr) -> [c_char; NI_MAXHOST] {
    let s = addr.to_string();
    let bytes = s.as_bytes();
    let mut caddr = [0 as c_char; NI_MAXHOST];
    // IPv6 address string is at most 45 bytes, always fits in NI_MAXHOST
    for (i, &b) in bytes.iter().enumerate() {
        caddr[i] = b as c_char;
    }
    caddr
}

fn build_tunnel_params(local: &Ipv6Addr, remote: &Ipv6Addr) -> IpTunParams {
    IpTunParams {
        link_id: 0,
        flags: IPTUN_PARAM_TYPE | IPTUN_PARAM_LADDR | IPTUN_PARAM_RADDR,
        ip_tun_type: IPTUN_TYPE_IPV6,
        l_addr: addr_to_caddr(&IpAddr::V6(*local)),
        r_addr: addr_to_caddr(&IpAddr::V6(*remote)),
        sec_info: IpsecReq {
            ipsr_ah_req: 0,
            ipsr_esp_req: 0,
            ipsr_self_encap_req: 0,
            ipsr_auth_alg: 0,
            ipsr_esp_alg: 0,
            ipsr_esp_auth_alg: 0,
        },
    }
}

fn open_dladm() -> Result<DladmHandle, u32> {
    let mut ptr: *mut c_void = std::ptr::null_mut();
    // SAFETY: FFI call with no outstanding preconditions.
    let status = unsafe { dladm_open(&mut ptr) };
    if status != DLADM_STATUS_OK {
        return Err(status);
    }
    // `DLADM_STATUS_OK` implies `ptr` is non-null (see `DladmHandle`
    // invariants), so constructing the wrapper here establishes both
    // struct invariants.
    Ok(DladmHandle { ptr })
}

fn open_ipadm() -> Result<IpadmHandle, u32> {
    let mut ptr: *mut c_void = std::ptr::null_mut();
    // SAFETY: FFI call with no outstanding preconditions.
    let status = unsafe { ipadm_open(&mut ptr, 0) };
    if status != IPADM_STATUS_OK {
        return Err(status);
    }
    // `IPADM_SUCCESS` implies `ptr` is non-null (see `IpadmHandle`
    // invariants), so constructing the wrapper here establishes both
    // struct invariants.
    Ok(IpadmHandle { ptr })
}

fn open_inet_dgram_socket() -> io::Result<OwnedFd> {
    // SAFETY: FFI call with no outstanding preconditions.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };

    if raw == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY:
    // - `raw` was returned by `libc::socket` and is non-negative
    //   (the prior `== -1` check rejects the error case), so it is a
    //   valid open file descriptor.
    // - `raw` was created by the call above and has not been observed
    //   by any other code, so this `from_raw_fd` is the sole owner.
    // - The returned `OwnedFd` will close the descriptor on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn parse_tunnel_addr(
    value: &[c_char; NI_MAXHOST],
    endpoint: &str,
) -> Result<Ipv6Addr, TunnelError> {
    let nul = value.iter().position(|&byte| byte == 0).ok_or_else(|| {
        TunnelError::StatusCheckFailed(format!("{endpoint} tunnel address is not NUL-terminated"))
    })?;

    let bytes: Vec<u8> = value[..nul].iter().map(|&byte| byte as u8).collect();

    let text = str::from_utf8(&bytes).map_err(|e| {
        TunnelError::StatusCheckFailed(format!("invalid {endpoint} tunnel address: {e}"))
    })?;

    text.parse::<Ipv6Addr>().map_err(|e| {
        TunnelError::StatusCheckFailed(format!("invalid {endpoint} IPv6 address {text:?}: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c_addr(value: &str) -> [c_char; NI_MAXHOST] {
        let mut result = [0; NI_MAXHOST];

        for (destination, source) in result.iter_mut().zip(value.bytes()) {
            *destination = source as c_char;
        }

        result
    }

    #[test]
    fn parses_ipv6_tunnel_address() {
        let value = c_addr("2001:db8::1");

        let address = parse_tunnel_addr(&value, "local").unwrap();

        assert_eq!(address, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn rejects_invalid_ipv6_tunnel_address() {
        let value = c_addr("not-an-address");

        let error = parse_tunnel_addr(&value, "remote").unwrap_err();

        assert!(error.to_string().contains("invalid remote IPv6 address"));
    }

    #[test]
    fn rejects_non_terminated_tunnel_address() {
        let value = [b'a' as c_char; NI_MAXHOST];

        let error = parse_tunnel_addr(&value, "local").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("local tunnel address is not NUL-terminated")
        );
    }

    #[tokio::test]
    #[ignore = "requires tunnel state prepared by crates/dslite-b4/scripts/test-illumos-observe.sh"]
    async fn sets_illumos_tunnel_mtu() {
        let name = std::env::var("DSLITE_TEST_TUNNEL")
            .expect("DSLITE_TEST_TUNNEL must name the prepared test tunnel");
        let mtu = std::env::var("DSLITE_TEST_MTU")
            .expect("DSLITE_TEST_MTU must contain the requested tunnel MTU")
            .parse()
            .expect("DSLITE_TEST_MTU must be an unsigned integer");
        let backend = IllumosBackend::new(name).unwrap();

        backend
            .update(TunnelUpdate {
                mtu: Some(mtu),
                bring_up: false,
            })
            .await
            .unwrap();

        assert_eq!(backend.get_mtu().unwrap(), mtu);
    }

    #[tokio::test]
    #[ignore = "requires tunnel state prepared by crates/dslite-b4/scripts/test-illumos-observe.sh"]
    async fn observes_illumos_tunnel() {
        let name = std::env::var("DSLITE_TEST_TUNNEL")
            .expect("DSLITE_TEST_TUNNEL must name the prepared test tunnel");
        let expected = std::env::var("DSLITE_TEST_EXPECT")
            .expect("DSLITE_TEST_EXPECT must be present-up, present-down, or absent");
        let backend = IllumosBackend::new(name).unwrap();

        let observed = backend.observe().await.unwrap();

        if expected == "absent" {
            assert_eq!(observed, Observed::Absent);
            return;
        }

        let local_v6 = std::env::var("DSLITE_TEST_LOCAL_V6")
            .expect("DSLITE_TEST_LOCAL_V6 must contain the prepared local endpoint")
            .parse()
            .expect("DSLITE_TEST_LOCAL_V6 must be an IPv6 address");
        let remote_v6 = std::env::var("DSLITE_TEST_REMOTE_V6")
            .expect("DSLITE_TEST_REMOTE_V6 must contain the prepared remote endpoint")
            .parse()
            .expect("DSLITE_TEST_REMOTE_V6 must be an IPv6 address");
        let mtu = std::env::var("DSLITE_TEST_MTU")
            .expect("DSLITE_TEST_MTU must contain the prepared tunnel MTU")
            .parse()
            .expect("DSLITE_TEST_MTU must be an unsigned integer");
        let admin_up = match expected.as_str() {
            "present-up" => true,
            "present-down" => false,
            value => panic!("unexpected DSLITE_TEST_EXPECT value: {value}"),
        };

        assert_eq!(
            observed,
            Observed::Present {
                local_v6,
                remote_v6,
                mtu,
                admin_up,
            }
        );
    }

    #[tokio::test]
    #[ignore = "requires tunnel state prepared by crates/dslite-b4/scripts/test-illumos-observe.sh"]
    async fn brings_up_illumos_tunnel() {
        let name = std::env::var("DSLITE_TEST_TUNNEL")
            .expect("DSLITE_TEST_TUNNEL must name the prepared test tunnel");
        let local_v6 = std::env::var("DSLITE_TEST_LOCAL_V6")
            .expect("DSLITE_TEST_LOCAL_V6 must contain the prepared local endpoint")
            .parse()
            .expect("DSLITE_TEST_LOCAL_V6 must be an IPv6 address");
        let remote_v6 = std::env::var("DSLITE_TEST_REMOTE_V6")
            .expect("DSLITE_TEST_REMOTE_V6 must contain the prepared remote endpoint")
            .parse()
            .expect("DSLITE_TEST_REMOTE_V6 must be an IPv6 address");
        let mtu = std::env::var("DSLITE_TEST_MTU")
            .expect("DSLITE_TEST_MTU must contain the prepared tunnel MTU")
            .parse()
            .expect("DSLITE_TEST_MTU must be an unsigned integer");
        let backend = IllumosBackend::new(name).unwrap();

        backend
            .update(TunnelUpdate {
                mtu: None,
                bring_up: true,
            })
            .await
            .unwrap();

        assert_eq!(
            backend.observe().await.unwrap(),
            Observed::Present {
                local_v6,
                remote_v6,
                mtu,
                admin_up: true,
            }
        );
    }
}
