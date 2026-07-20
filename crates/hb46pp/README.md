# hb46pp

`hb46pp` is a Rust client for the
[HTTP-Based IPv4 over IPv6 Provisioning Protocol][hb46pp-spec] used to discover
provisioning parameters for IPv4-over-IPv6 methods. It implements bootstrap TXT
discovery, request and response validation, IPv6-only HTTP transport, protocol
redirects, and retry timing guidance.

Provisioning data for each supported IPv4-over-IPv6 method is retained as
JSON. Applications select a method and interpret its parameters.

## Example

The default features provide a [Hickory][hickory] DNS resolver and a
[Reqwest][reqwest] HTTP transport:

```rust
# #[cfg(feature = "default-client")]
# mod example {
use hb46pp::{Capability, FirmwareVersion, Product, ProvisioningRequest, VendorId};
use hb46pp::client::{DefaultClient, ProvisioningOutcome};

async fn provision() -> Result<(), Box<dyn std::error::Error>> {
    let request = ProvisioningRequest::new(
        "000000".parse::<VendorId>()?,
        "example-router".parse::<Product>()?,
        "1_0_0".parse::<FirmwareVersion>()?,
        vec![Capability::DsLite],
        None,
        None,
    )?;
    let client = DefaultClient::try_new()?;

    let outcome = client.provision(&request).await?;
    let window = outcome.next_attempt_window();

    match outcome {
        ProvisioningOutcome::Provisioned(response) => {
            if let Some(offer) = response.data().select(&[Capability::DsLite]) {
                println!("DS-Lite parameters: {}", offer.parameters());
            }
        }
        ProvisioningOutcome::NotFound => {
            println!("HB46PP is not available on this network");
        }
    }
    println!(
        "make another attempt after a delay between {:?} and {:?}",
        window.min(),
        window.max()
    );

    Ok(())
}
# }
```

The library reports when HB46PP recommends making the next request, but does
not choose a random delay, sleep, monitor network changes, or persist
provisioning data. Those responsibilities remain with the application.

## Features

- `default-client` (default): default DNS resolver and HTTP transport.
- `client`: protocol flow and adapter traits without concrete network adapters.
- `default-resolver`: Hickory-based discovery resolver.
- `default-transport`: Reqwest-based IPv6-only HTTP transport.
- No features: protocol models and validation only.

Custom transports must use IPv6, apply the requested TLS policy, avoid
automatic redirects, and bound response resource usage.

## License

Licensed under either of the following:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

[hb46pp-spec]: https://github.com/v6pc/v6mig-prov/blob/9020a1bd5f2f8f83712b1180db70af7dc0dad638/spec.md
[hickory]: https://crates.io/crates/hickory-resolver
[reqwest]: https://crates.io/crates/reqwest
