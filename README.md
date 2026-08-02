# IPv4 over IPv6

Rust implementations of IPv4 over IPv6 protocols and supporting tools.

## Workspace

- [`dslite-b4`](crates/dslite-b4) manages a DS-Lite B4 tunnel on Linux and
  illumos.
- [`hb46pp`](crates/hb46pp) implements the HTTP Based IPv4 over IPv6
  Provisioning Protocol.

## Building

```text
cargo build --workspace
```

## Testing

```text
cargo test --workspace
```

## License

Each workspace package is available under the MIT or Apache 2.0 license. See
the package directory for its license files.
