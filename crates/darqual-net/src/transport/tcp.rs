//! TCP transport implementation of the [`Transport`] trait.

/// Marker struct for the TCP transport.
///
/// The actual implementation lives in `transport::mod` via the `impl Transport`
/// block — this type just serves as the tag.
#[derive(Debug, Clone, Copy)]
pub struct TcpTransport;
