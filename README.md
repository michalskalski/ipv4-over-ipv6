# IPv4 over IPv6

[![CI](https://github.com/michalskalski/ipv4-over-ipv6/actions/workflows/ci.yml/badge.svg)](https://github.com/michalskalski/ipv4-over-ipv6/actions/workflows/ci.yml)

Rust implementations of IPv4 over IPv6 protocols and the Unix services that
use them.

| Package | Purpose | Documentation |
| --- | --- | --- |
| [`dslite-b4`](crates/dslite-b4) | DS Lite B4 tunnel management daemon for Linux and illumos | [docs.rs](https://docs.rs/dslite-b4) · [crates.io](https://crates.io/crates/dslite-b4) |
| [`hb46pp`](crates/hb46pp) | Client library for the HTTP Based IPv4 over IPv6 Provisioning Protocol | [docs.rs](https://docs.rs/hb46pp) · [crates.io](https://crates.io/crates/hb46pp) |

## Building

```console
cargo build --workspace
```

## Testing

```console
cargo test --workspace
```

## License

Each workspace package is available under the MIT or Apache 2.0 license. See
the package directory for its license files.
