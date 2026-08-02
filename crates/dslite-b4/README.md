# dslite-b4

`dslite-b4` configures a Linux or illumos host to provide the B4 function in
the DS-Lite architecture defined by RFC 6333. It establishes IPv4 connectivity
through an IPv4 in IPv6 tunnel to an AFTR. The daemon configures a tunnel
network interface, its IPv6 endpoints, the B4 IPv4 address, and an IPv4 default
route. The operating system networking stack performs packet encapsulation and
forwarding.

The package provides the `dslite-b4` executable and a Rust library containing
the configuration, discovery, reconciliation, runtime state, status, and
platform backend modules. Linux and illumos are supported.

## Building

From the workspace root:

```text
cargo build --release -p dslite-b4
cargo test -p dslite-b4
```

## Configuration

The executable reads `/etc/dslite-b4.toml` by default. Another path can be
selected with `--config`. See [`example-config.toml`](example-config.toml) for
the available sections and defaults.

Validate a configuration before starting the daemon:

```text
dslite-b4 check-config
```

## License

Licensed under either of the following:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
