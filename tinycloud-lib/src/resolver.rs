use ssi::dids::AnyDidMethod as DIDMethods;

lazy_static::lazy_static! {
    // Initialize with default methods, remove lifetime parameter
    pub static ref DID_METHODS: DIDMethods = DIDMethods::default();
}
