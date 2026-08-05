# dslite-b4

`dslite-b4` is a Unix daemon that provides the B4 function from
[RFC 6333][rfc-6333] on Linux and illumos. It establishes IPv4 connectivity
through an IPv4 in IPv6 tunnel to an AFTR. It continues to reconcile the
configured tunnel with operating system state.

The daemon runs as root. It creates and manages a tunnel interface, assigns the
reserved B4 IPv4 endpoint, and installs an IPv4 default route through that
interface. Packet encapsulation and forwarding remain in the operating system
network stack.

## Install

Install the executable from crates.io:

```console
cargo install dslite-b4
```

`cargo install` installs only the executable. The crate also contains an
example configuration, `dslite-b4(8)` and `dslite-b4.toml(5)` manual pages,
and service definitions for systemd and illumos SMF.

System packages should install the executable as `/usr/sbin/dslite-b4`, the
configuration as `/etc/dslite-b4.toml`, and the manuals under
`/usr/share/man`. The systemd unit is intended for `/usr/lib/systemd/system`.
The SMF manifest and method are intended for `/lib/svc/manifest/network` and
`/lib/svc/method`.

## Configure and run

The executable reads `/etc/dslite-b4.toml` by default. Another path can be
selected with `--config`. The packaged
[`example-config.toml`][example-config] describes every setting and its
default.

Validate a configuration before starting the daemon:

```console
dslite-b4 check-config
```

Run it in the foreground, normally under systemd or SMF:

```console
dslite-b4 run
```

Inspect the last operational snapshot with `dslite-b4 status`. Use
`dslite-b4 status --json` for output intended for programs. `set-aftr` and
`clear-aftr` update the runtime AFTR override and signal a running daemon to
reconcile immediately.

## AFTR selection

An AFTR may be configured statically, supplied at runtime, or discovered using
the optional HB46PP integration enabled by default. Static configuration takes
precedence over the runtime value, which takes precedence over discovery.

HB46PP discovery accepts only provisioning servers using certificate validation
(`t=b`) by default. Providers requiring `t=a` can be enabled explicitly with
`discovery.allow_unauthenticated`, which permits HTTP or HTTPS without
certificate validation. HB46PP still trusts the access network DNS response to
select the provisioning server hostname.

## Building

From the workspace root:

```console
cargo build --release -p dslite-b4
cargo test -p dslite-b4
```

## License

Licensed under either of the following:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

[example-config]: https://github.com/michalskalski/ipv4-over-ipv6/blob/main/crates/dslite-b4/example-config.toml
[rfc-6333]: https://www.rfc-editor.org/rfc/rfc6333
