use ssi::dids::AnyDidMethod;

lazy_static::lazy_static! {
    pub static ref DID_METHODS: AnyDidMethod = AnyDidMethod::default();
}
