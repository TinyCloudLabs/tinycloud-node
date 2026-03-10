/// Protocol version shared between TinyCloud server and SDK.
///
/// Both the server binary and WASM SDK depend on tinycloud-lib,
/// so this constant is shared at compile time. SDK and node must
/// have matching protocol versions to communicate.
pub const PROTOCOL_VERSION: u32 = 1;
