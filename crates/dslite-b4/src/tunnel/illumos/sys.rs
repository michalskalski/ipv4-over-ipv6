//! illumos C ABI bindings: constants, FFI declarations, and `repr(C)`
//! struct mirrors.
use std::{
    ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_ushort, c_void},
    io,
    mem::MaybeUninit,
    net::Ipv4Addr,
    ptr,
};

// libdladm constants

/// `dladm_status_t::DLADM_STATUS_OK`.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdladm.h#L104>
pub const DLADM_STATUS_OK: u32 = 0;

/// `dladm_status_t::DLADM_STATUS_NOTFOUND`.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdladm.h#L109>
pub const DLADM_STATUS_NOTFOUND: u32 = 5;

/// `DLADM_OPT_ACTIVE`, apply changes to the active configuration only
/// (not the persistent SMF-managed state).
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdladm.h#L86>
pub const DLADM_OPT_ACTIVE: c_uint = 0x0000_0001;

/// `IPTUN_PARAM_*`, bitfield in `IpTunParams.flags` telling libdladm which
/// fields of the struct are populated.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdliptun.h#L49-L51>
pub const IPTUN_PARAM_TYPE: c_uint = 0x0000_0001;
pub const IPTUN_PARAM_LADDR: c_uint = 0x0000_0002;
pub const IPTUN_PARAM_RADDR: c_uint = 0x0000_0004;

// libipadm constants

/// `ipadm_status_t::IPADM_SUCCESS`.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libipadm/common/libipadm.h#L62>
pub const IPADM_STATUS_OK: u32 = 0;

/// `IPADM_OPT_ACTIVE`, apply to live config only.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libipadm/common/libipadm.h#L162>
pub const IPADM_OPT_ACTIVE: u32 = 0x0000_0002;

// POSIX socket / netdb constants
pub const AF_INET: u16 = libc::AF_INET as u16;
pub const NI_MAXHOST: usize = libc::NI_MAXHOST as usize;

// libdladm + libipadm FFI
//
// Linkage configured in build.rs (-ldladm, -lipadm).
// Source: usr/src/lib/libdladm/, usr/src/lib/libipadm/ in illumos-gate.

unsafe extern "C" {
    // libdladm
    pub fn dladm_open(handle: *mut *mut c_void) -> u32;
    pub fn dladm_close(handle: *mut c_void);
    pub fn dladm_iptun_create(
        handle: *mut c_void,
        name: *const c_char,
        params: *mut IpTunParams,
        flags: c_uint,
    ) -> u32;
    pub fn dladm_iptun_delete(handle: *mut c_void, link_id: u32, flags: c_uint) -> u32;
    pub fn dladm_iptun_getparams(
        handle: *mut c_void,
        params: *mut IpTunParams,
        flags: c_uint,
    ) -> u32;
    pub fn dladm_name2info(
        handle: *mut c_void,
        name: *const c_char,
        linkid: *mut u32,
        flags: *mut u32,
        class: *mut u32,
        media: *mut u32,
    ) -> u32;

    // libipadm: interface lifecycle (works on 64-bit; ipmgmt_if_arg_t has no size_t)
    pub fn ipadm_open(handle: *mut *mut c_void, flags: u32) -> u32;
    pub fn ipadm_close(handle: *mut c_void);
    pub fn ipadm_create_if(handle: *mut c_void, name: *mut c_char, family: u16, flags: u32) -> u32;
    pub fn ipadm_delete_if(
        handle: *mut c_void,
        name: *const c_char,
        family: u16,
        flags: u32,
    ) -> u32;
}

// `struct lifreq` mirror
//
// `lifreq` is an illumos-specific extension of POSIX `ifreq`.
//
// Used for the SIOCSLIF* ioctls that assign the IPv4 address directly,
// bypassing libipadm (issue 17851). The kernel reads/writes our memory
// at this layout, so it must match C exactly. Layout verified on OmniOS
// r151054 via crates/dslite-b4/scripts/probe_lifreq.c, re-run that probe if the size
// assertion below ever fails.
//
// Initialized via `MaybeUninit::zeroed().assume_init()` rather than a
// struct literal. A struct-literal init of the embedded `LifrLifru`
// union picks one variant (e.g. `flags: 0u64`), but bytes beyond that
// variant's size are padding with unspecified contents. The kernel ABI
// expects a fully-zeroed buffer for unused bytes, both to avoid leaking
// stack data into the kernel and to remain correct across SIOCSLIF*
// variants that read different shapes from the same union slot.

/// `_LIFNAMSIZ`.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/if.h#L345>
pub const LIFNAMSIZ: usize = 32;

/// `_pad` pulls the union size up to 336 bytes, matching the
/// largest C variant (`lif_nd_req` / `lif_ifinfo_req`).
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/if.h#L372-L389>
#[repr(C)]
pub union LifrLifru {
    pub addr: libc::sockaddr_storage,
    pub flags: u64,
    _pad: [u8; 336],
}

/// `struct lifreq`, argument for SIOCSLIF* ioctls. `lifr_lifru1` is a
/// placeholder for the not used union.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/if.h#L359-L401>
#[repr(C)]
pub struct Lifreq {
    pub lifr_name: [c_char; LIFNAMSIZ],
    pub lifr_lifru1: u32,
    pub lifr_type: u32,
    pub lifr_lifru: LifrLifru,
}

const _: () = assert!(std::mem::size_of::<Lifreq>() == 376);

// kernel ioctl request encoding
// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/sys/ioccom.h>

/// `IOCPARM_MASK`, low byte of the encoded struct size.
pub const IOCPARM_MASK: u32 = 0xff;

/// `IOC_OUT`, kernel writes the user buffer.
pub const IOC_OUT: u32 = 0x4000_0000;

/// `IOC_IN`, kernel reads the user buffer.
pub const IOC_IN: u32 = 0x8000_0000;

/// `IOC_INOUT`, kernel reads then writes.
pub const IOC_INOUT: u32 = IOC_IN | IOC_OUT;

/// Encode an ioctl request number, mirroring `_IOW`/`_IOWR` from
/// `<sys/ioccom.h>`. `direction` is one of `IOC_IN`/`IOC_OUT`/`IOC_INOUT`,
/// `group` is the magic letter (e.g. `b'i'` for IP), `num` is the request
/// number within that group. Struct size is taken from `Lifreq` since every
/// SIOCSLIF* ioctl uses it.
pub const fn ioc(direction: u32, group: u8, num: u8) -> u32 {
    let size = (std::mem::size_of::<Lifreq>() & IOCPARM_MASK as usize) as u32;
    direction | (size << 16) | ((group as u32) << 8) | num as u32
}

// SIOCSLIF* ioctl numbers
// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/sys/sockio.h#L158-L175>

/// `SIOCSLIFADDR`, set local IP address.
pub const SIOCSLIFADDR: u32 = ioc(IOC_IN, b'i', 112);

/// `SIOCSLIFDSTADDR`, set point-to-point peer address.
pub const SIOCSLIFDSTADDR: u32 = ioc(IOC_IN, b'i', 114);

/// `SIOCSLIFFLAGS`, set interface flags (writes `lifr_lifru.flags`).
pub const SIOCSLIFFLAGS: u32 = ioc(IOC_IN, b'i', 116);

/// `SIOCGLIFFLAGS`, get interface flags.
pub const SIOCGLIFFLAGS: u32 = ioc(IOC_INOUT, b'i', 117);

/// `SIOCSLIFNETMASK`, set subnet mask.
pub const SIOCSLIFNETMASK: u32 = ioc(IOC_IN, b'i', 126);

/// `IFF_UP`, address is up. The flags slot in `lifr_lifru` is 64-bit.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/if.h#L106>
pub const IFF_UP: u64 = 0x0000_0000_0000_0001;

// libdladm IPsec / iptun parameter structs
//
// Argument types for `dladm_iptun_create`. The IPsec fields are unused,
// DS-Lite is plain IPv4-in-IPv6 but the struct shape has to match.

/// `ipsec_req_t`.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/netinet/in.h#L962>
#[repr(C)]
pub struct IpsecReq {
    pub ipsr_ah_req: c_uint,
    pub ipsr_esp_req: c_uint,
    pub ipsr_self_encap_req: c_uint,
    pub ipsr_auth_alg: u8,
    pub ipsr_esp_alg: u8,
    pub ipsr_esp_auth_alg: u8,
}

/// `iptun_type_t`.
///
/// This FFI type is represented as an integer rather than a Rust enum
/// because C may write any value into it. In particular, an all-zero
/// `IpTunParams` output buffer must be valid before
/// `dladm_iptun_getparams` populates it.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/inet/iptun.h#L58>
pub type IpTunType = u32;

/// `IPTUN_TYPE_IPV6`, IPv4-in-IPv6 for DS-Lite.
pub const IPTUN_TYPE_IPV6: IpTunType = 2;

/// `iptun_params_t`. Address fields are NUL-terminated printable strings up to NI_MAXHOST bytes.
/// Libdladm calls getaddrinfo internally to parse them.
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/lib/libdladm/common/libdliptun.h#L46>
#[repr(C)]
pub struct IpTunParams {
    pub link_id: u32,
    pub flags: c_uint,
    pub ip_tun_type: IpTunType,
    pub l_addr: [c_char; NI_MAXHOST],
    pub r_addr: [c_char; NI_MAXHOST],
    pub sec_info: IpsecReq,
}

// Build a zero-initialized `Lifreq` with `lifr_name` populated from a
// `&CStr`. Shared between `set_lifr_addr` and `bring_up` as the prelude
// before issuing SIOCSLIF* ioctls. Returns `InvalidInput` when `name`
// would not fit (>= LIFNAMSIZ bytes).
fn lifreq_for_name(name: &CStr) -> io::Result<Lifreq> {
    if name.count_bytes() > LIFNAMSIZ - 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    // SAFETY: `Lifreq` is `#[repr(C)]` and every field has a valid all-zero
    // bit pattern: `[c_char; 32]` is NUL bytes, both `u32` fields are 0,
    // and the `LifrLifru` union admits zero in every variant
    // (`sockaddr_storage` with `sin_family = AF_UNSPEC`, `u64` flags = 0,
    // `[u8; 336]`). No field is a reference, `NonNull`, `bool`, or niche
    // enum, so no invalid bit pattern is constructed.
    let mut lr: Lifreq = unsafe { MaybeUninit::zeroed().assume_init() };

    let src = name.to_bytes();
    // SAFETY:
    // - `src` from `name.to_bytes()` is a `&[u8]`, valid for reads of
    //   `src.len()` bytes by the slice-reference guarantee.
    // - `lr.lifr_name` is a `[c_char; 32]` field of the stack-local
    //   `Lifreq`, valid for 32 writes.
    // - `src.len() <= LIFNAMSIZ - 1` (= 31 < 32) by the prior
    //   `count_bytes()` check, so the copy stays within `lifr_name`.
    // - Both pointers are `u8`-typed. `align_of::<u8>() == 1`, easy
    //   satisfied.
    // - `name`'s allocation and the stack-local `lr` are distinct, so
    //   the regions cannot overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            src.as_ptr(),
            lr.lifr_name.as_mut_ptr().cast::<u8>(),
            src.len(),
        )
    };

    Ok(lr)
}

// Shared body for the SIOCSLIF* ioctls that take an IPv4 address in the
// `lifr_lifru.addr` slot (SIOCSLIFADDR, SIOCSLIFDSTADDR, SIOCSLIFNETMASK).
// Builds a `Lifreq` shaped like this and fires `ioctl_num`:
//
//   offset                                   size
//      0  +--------------------------------+
//         | lifr_name      "<name>\0..."   |  32
//     32  +--------------------------------+
//         | lifr_lifru1    0               |   4
//     36  +--------------------------------+
//         | lifr_type      0               |   4
//     40  +--------------------------------+
//         | lifr_lifru.addr  (union slot)  | 336
//         |   as sockaddr_in:              |
//         |     sin_family = AF_INET    +0 |
//         |     sin_port   = 0          +2 |
//         |     sin_addr   = addr (BE)  +4 |
//         |     sin_zero   = 0...       +8 |
//         |   ...rest of the 336 zero...   |
//    376  +--------------------------------+
//
// `lifr_lifru` is a union: the same 336 bytes can be read as
// `sockaddr_storage`, `u64` (flags), etc. The variant used here is
// `sockaddr_in`. The kernel reads `sin_family` and only consumes the
// first 16 bytes. Everything past that stays zero from the zeroed init.
//
// Pointer casts on the address copy:
//
//   `copy_nonoverlapping<T>(src, dst, count)` copies count*sizeof(T)
//   bytes and needs src and dst to agree on T. The source is
//   `*const sockaddr_in` (16B), the destination is
//   `*mut sockaddr_storage` (128B). Casting both to `*u8` makes T = u8
//   and `count` a byte count, so the types unify and 16 bytes are
//   copied.
//
//   `&raw const x` / `&raw mut x` give a raw pointer without the
//   initialized + aligned + exclusive-borrow promises that `&` / `&mut`
//   carry. That matters for union fields, where no single variant is
//   "the" live one, and a `&mut lr.lifr_lifru.addr` would be claiming
//   the bytes are validly a sockaddr_storage right now.

/// Issue a SIOCSLIF* ioctl that takes an IPv4 address in the
/// `lifr_lifru.addr` slot.
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls. AF_INET / SOCK_DGRAM is the standard
///   choice on illumos.
/// - `ioctl_num` must be one of `SIOCSLIFADDR`, `SIOCSLIFDSTADDR`, or
///   `SIOCSLIFNETMASK`. Each of these expects a `Lifreq` with the
///   address slot of `lifr_lifru` populated. Other SIOCSLIF* numbers
///   (e.g. `SIOCSLIFFLAGS`) consume a different union slot and would
///   misinterpret the address-shaped buffer this function builds.
unsafe fn set_lifr_addr(
    sock_fd: c_int,
    name: &CStr,
    ioctl_num: u32,
    addr: Ipv4Addr,
) -> io::Result<()> {
    let mut lr = lifreq_for_name(name)?;

    // Build the sockaddr_in. `s_addr` is network byte order.
    // `Ipv4Addr` -> `u32` is host order, flip with `to_be`.
    let sin = libc::sockaddr_in {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
    };

    // Splat the 16 bytes of `sin` over the leading bytes of the union slot.
    // SAFETY:
    // - `sin` is a fully-initialized `sockaddr_in` on the stack, valid
    //   for reads of `size_of::<sockaddr_in>()` (= 16) bytes.
    // - `lr.lifr_lifru` is a 336-byte union slot in the stack-local
    //   `Lifreq`. `&raw mut` produces an address-only raw pointer (no
    //   variant-validity or exclusivity claim), and 16 bytes fits within
    //   336.
    // - Both pointers are `u8`-typed. `align_of::<u8>() = 1`, satisfied.
    // - `sin` and `lr` are distinct stack locals, so the regions cannot
    //   overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            (&raw const sin).cast::<u8>(),
            (&raw mut lr.lifr_lifru.addr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    };
    // `ioctl_num as _`: libc's ioctl request type differs between illumos
    // (`c_int`) and Linux (`c_ulong`). Inferred cast keeps both happy
    // for rust-analyzer when developing on Linux.
    // SAFETY:
    // - `sock_fd` is a valid socket fd suitable for SIOCSLIF* ioctls
    //   (caller's contract, see `# Safety` on this function).
    // - `ioctl_num` is one of SIOCSLIFADDR / SIOCSLIFDSTADDR /
    //   SIOCSLIFNETMASK, all of which expect a `Lifreq` with the
    //   address slot of `lifr_lifru` populated (caller's contract).
    // - `&raw mut lr` points to a fully-initialized 376-byte `Lifreq`.
    //   The name and `lifr_lifru.addr` slot were populated by the
    //   blocks above, the rest is zero from the initial zero-init.
    //   `lr` lives until function return, covering the call duration.
    let rc = unsafe { libc::ioctl(sock_fd, ioctl_num as _, &raw mut lr) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Set the local IPv4 address on `name` (SIOCSLIFADDR).
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls (AF_INET / SOCK_DGRAM is the standard
///   choice on illumos).
pub unsafe fn set_local_addr(sock_fd: c_int, name: &CStr, addr: Ipv4Addr) -> io::Result<()> {
    // SAFETY:
    // - `sock_fd` validity is forwarded from this function's `# Safety`
    //   contract.
    // - `SIOCSLIFADDR` is among the ioctl numbers documented as valid
    //   for `set_lifr_addr`.
    unsafe { set_lifr_addr(sock_fd, name, SIOCSLIFADDR, addr) }
}

/// Set the point-to-point peer (destination) address on `name` (SIOCSLIFDSTADDR).
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls (AF_INET / SOCK_DGRAM is the standard
///   choice on illumos).
pub unsafe fn set_dst_addr(sock_fd: c_int, name: &CStr, addr: Ipv4Addr) -> io::Result<()> {
    // SAFETY:
    // - `sock_fd` validity is forwarded from this function's `# Safety`
    //   contract.
    // - `SIOCSLIFDSTADDR` is among the ioctl numbers documented as valid
    //   for `set_lifr_addr`.
    unsafe { set_lifr_addr(sock_fd, name, SIOCSLIFDSTADDR, addr) }
}

/// Set the IPv4 subnet mask on `name` (SIOCSLIFNETMASK). `mask` is the
/// bit pattern (e.g. `255.255.255.248` for /29), not a prefix length.
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls (AF_INET / SOCK_DGRAM is the standard
///   choice on illumos).
pub unsafe fn set_netmask(sock_fd: c_int, name: &CStr, mask: Ipv4Addr) -> io::Result<()> {
    // SAFETY:
    // - `sock_fd` validity is forwarded from this function's `# Safety`
    //   contract.
    // - `SIOCSLIFNETMASK` is among the ioctl numbers documented as valid
    //   for `set_lifr_addr`.
    unsafe { set_lifr_addr(sock_fd, name, SIOCSLIFNETMASK, mask) }
}

/// Bring `name` up by OR-ing IFF_UP into its existing flags. Read-modify-write
/// pair (SIOCGLIFFLAGS then SIOCSLIFFLAGS) so other kernel-set flags
/// (RUNNING, BROADCAST, MULTICAST, ...) are not clobbered. The flags slot
/// is a different variant of `lifr_lifru` than the address slot used by the
/// SIOCSLIFADDR family.
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls (AF_INET / SOCK_DGRAM is the standard
///   choice on illumos).
pub unsafe fn bring_up(sock_fd: c_int, name: &CStr) -> io::Result<()> {
    let mut lr = lifreq_for_name(name)?;

    // SAFETY:
    // - `sock_fd` is a valid socket fd suitable for SIOCSLIF* ioctls
    //   (caller's contract).
    // - `SIOCGLIFFLAGS` reads interface flags from the kernel into the
    //   `flags` slot of `lifr_lifru`, expecting a `Lifreq` argument.
    // - `&raw mut lr` points to a fully-initialized 376-byte `Lifreq`
    //   produced by `lifreq_for_name`. `lr` lives until function return.
    let rc = unsafe { libc::ioctl(sock_fd, SIOCGLIFFLAGS as _, &raw mut lr) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: SIOCGLIFFLAGS just populated `lr.lifr_lifru.flags` with a
    // `u64` from the kernel, so reading that union slot as `u64` is sound.
    unsafe { lr.lifr_lifru.flags |= IFF_UP };

    // SAFETY:
    // - `sock_fd` is a valid socket fd (caller's contract).
    // - `SIOCSLIFFLAGS` writes the kernel's interface flags from the
    //   `flags` slot of `lifr_lifru`, expecting a `Lifreq` argument.
    // - `&raw mut lr` points to a fully-initialized `Lifreq` whose
    //   `flags` slot was just updated. `lr` lives until function return.
    let rc = unsafe { libc::ioctl(sock_fd, SIOCSLIFFLAGS as _, &raw mut lr) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Return whether `name` has `IFF_UP` set.
///
/// # Safety
///
/// - `sock_fd` must be a valid, open file descriptor for a socket that
///   accepts SIOCSLIF* ioctls (AF_INET / SOCK_DGRAM is the standard
///   choice on illumos).
pub unsafe fn is_up(sock_fd: c_int, name: &CStr) -> io::Result<bool> {
    let mut lr = lifreq_for_name(name)?;

    // SAFETY:
    // - `sock_fd` is a valid socket fd suitable for SIOCSLIF* ioctls
    //   (caller's contract).
    // - `SIOCGLIFFLAGS` reads interface flags from the kernel into the
    //   `flags` slot of `lifr_lifru`, expecting a `Lifreq` argument.
    // - `&raw mut lr` points to a fully-initialized 376-byte `Lifreq`
    //   produced by `lifreq_for_name`. `lr` lives until function return.
    let rc = unsafe { libc::ioctl(sock_fd, SIOCGLIFFLAGS as _, &raw mut lr) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: SIOCGLIFFLAGS just populated `lr.lifr_lifru.flags` with a
    // `u64` from the kernel, so reading that union slot as `u64` is sound.
    let flags = unsafe { lr.lifr_lifru.flags };

    Ok((flags & IFF_UP) != 0)
}

// PF_ROUTE <net/route.h>

// Typed to match the destination fields in rt_msghdr
pub const RTM_VERSION: c_uchar = 3;
pub const RTM_ADD: c_uchar = 0x1;
pub const RTM_DELETE: c_uchar = 0x2;
pub const RTM_NEWADDR: c_uchar = 0xc;
pub const RTM_DELADDR: c_uchar = 0xd;
pub const RTM_CHGADDR: c_uchar = 0xf;
pub const RTM_FREEADDR: c_uchar = 0x10;

pub const RTF_UP: c_int = 0x1;
pub const RTF_GATEWAY: c_int = 0x2;
pub const RTF_STATIC: c_int = 0x800;

pub const RTA_DST: c_int = 0x1;
pub const RTA_GATEWAY: c_int = 0x2;
pub const RTA_NETMASK: c_int = 0x4;

/// Routing metrics carried inside `rt_msghdr` (10 × u32, 40 bytes).
/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/route.h#L72-L84>
#[derive(Default)]
#[repr(C)]
pub struct rt_metrics {
    pub rmx_locks: u32,
    pub rmx_mtu: u32,
    pub rmx_hopcount: u32,
    pub rmx_expire: u32,
    pub rmx_recvpipe: u32,
    pub rmx_sendpipe: u32,
    pub rmx_ssthresh: u32,
    pub rmx_rtt: u32,
    pub rmx_rttvar: u32,
    pub rmx_pksent: u32,
}

const _: () = assert!(std::mem::size_of::<rt_metrics>() == 40);

/// <https://github.com/illumos/illumos-gate/blob/0764e87f4a667f36d63262fcdd690064929acc48/usr/src/uts/common/net/route.h#L152-L165>
#[derive(Default)]
#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: c_ushort,
    pub rtm_version: c_uchar,
    pub rtm_type: c_uchar,
    pub rtm_index: c_ushort,
    pub rtm_flags: c_int,
    pub rtm_addrs: c_int,
    pub rtm_pid: c_int,
    pub rtm_seq: c_int,
    pub rtm_errno: c_int,
    pub rtm_use: c_int,
    pub rtm_inits: c_uint,
    pub rtm_rmx: rt_metrics,
}

const _: () = assert!(std::mem::size_of::<rt_msghdr>() == 76);

pub fn sockaddr_in_v4(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
    }
}
