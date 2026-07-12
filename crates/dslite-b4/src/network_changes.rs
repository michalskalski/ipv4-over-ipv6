#[cfg(target_os = "linux")]
use futures_util::StreamExt;
#[cfg(target_os = "linux")]
use rtnetlink::{
    MulticastGroup, new_multicast_connection, packet_core::NetlinkMessage,
    packet_route::RouteNetlinkMessage,
};
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "illumos")]
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    time::Duration,
};
#[cfg(target_os = "illumos")]
use tokio::io::{Interest, unix::AsyncFd};

#[cfg(target_os = "illumos")]
use crate::tunnel::illumos::{
    RTM_ADD, RTM_CHGADDR, RTM_DELADDR, RTM_DELETE, RTM_FREEADDR, RTM_NEWADDR, rt_msghdr,
};

#[cfg(target_os = "linux")]
pub struct NetworkChanges {
    messages: futures_channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        rtnetlink::sys::SocketAddr,
    )>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl NetworkChanges {
    pub fn new() -> anyhow::Result<Self> {
        let (connection, _, messages) = new_multicast_connection(&[
            MulticastGroup::Link,
            MulticastGroup::Ipv6Ifaddr,
            MulticastGroup::Ipv6Route,
        ])?;
        let task = tokio::spawn(connection);
        Ok(Self { messages, task })
    }

    pub async fn changed(&mut self) -> anyhow::Result<()> {
        let Some((_message, _)) = self.messages.next().await else {
            return Err(anyhow::anyhow!("network-change event stream ended"));
        };

        let mut count = 1;

        while let Ok(Some((_, _))) =
            tokio::time::timeout(Duration::from_millis(100), self.messages.next()).await
        {
            count += 1;
        }

        tracing::debug!(count, "network-change hints received");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetworkChanges {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(target_os = "illumos")]
pub struct NetworkChanges {
    socket: AsyncFd<OwnedFd>,
}

#[cfg(target_os = "illumos")]
impl NetworkChanges {
    pub fn new() -> anyhow::Result<Self> {
        // SAFETY: FFI call with no outstanding preconditions.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY:
        // - `raw` was returned by `libc::socket` and is non-negative
        //   (the prior `< 0` check rejects the error case), so it is a
        //   valid open file descriptor.
        // - `raw` was created by the call above and has not been observed
        //   by any other code, so this `from_raw_fd` is the sole owner.
        // - The returned `OwnedFd` will close the descriptor on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        set_nonblocking(fd.as_raw_fd())?;

        Ok(Self {
            socket: AsyncFd::with_interest(fd, Interest::READABLE)?,
        })
    }

    pub async fn changed(&mut self) -> anyhow::Result<()> {
        self.read_next_wake_hint().await?;

        let mut count = 1;

        // Drain raw route messages, not just wake-worthy ones.
        // Disallowed messages can sit between useful hints in the same PF_ROUTE burst.
        loop {
            match tokio::time::timeout(Duration::from_millis(100), self.read_next_route_message())
                .await
            {
                Ok(Ok(Some(msg_type))) if is_wake_route_type(msg_type) => {
                    count += 1;
                }
                Ok(Ok(Some(_))) | Ok(Ok(None)) => {
                    continue;
                }
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => break,
            }
        }
        tracing::debug!(count, "network-change hints received");
        Ok(())
    }

    async fn read_next_wake_hint(&mut self) -> anyhow::Result<()> {
        loop {
            match self.read_next_route_message().await? {
                Some(msg_type) if is_wake_route_type(msg_type) => return Ok(()),
                Some(_) | None => continue,
            }
        }
    }

    async fn read_next_route_message(&mut self) -> anyhow::Result<Option<u8>> {
        loop {
            let mut guard = self.socket.readable().await?;
            match guard.try_io(|inner| read_route_hint(inner.get_ref().as_raw_fd())) {
                Ok(result) => return result.map_err(Into::into),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(target_os = "illumos")]
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: FFI call. `fd` is a live file descriptor owned by caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: FFI call. `fd` is a live file descriptor owned by caller.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn read_route_hint(fd: RawFd) -> io::Result<Option<u8>> {
    let mut buf = [0u8; 2048];

    // SAFETY: FFI call. Buffer is writable for `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "PF_ROUTE event stream ended",
        ));
    }
    if (n as usize) < size_of::<rt_msghdr>() {
        return Ok(None);
    }

    // SAFETY: `n >= size_of::<rt_msghdr>()` checked above.
    let hdr: rt_msghdr = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<rt_msghdr>()) };

    Ok(Some(hdr.rtm_type))
}

#[cfg(target_os = "illumos")]
fn is_wake_route_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        RTM_ADD | RTM_DELETE | RTM_NEWADDR | RTM_DELADDR | RTM_CHGADDR | RTM_FREEADDR
    )
}
