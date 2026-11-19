//! What storage sees of the node's at-rest state, per operation (TC-887).
//!
//! The node owns the keyring and the mode; block stores and the SQL artifact
//! repository read a fresh [`AtRestView`] from an [`AtRestSource`] for each
//! operation, because keys arrive after migrations and may unlock later.
//!
//! Rules every store follows (`docs/at-rest/INTERFACES.md`):
//! - mode `off` writes plaintext exactly as before;
//! - any other mode seals iff [`AtRestView::encrypting`], else the write fails
//!   (503), never a plaintext fallback;
//! - sealed data is read whenever keys exist; legacy plaintext is read unless
//!   the mode is `strict`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{DataKeyProvider, ObjectNameKey};

/// `at_rest.mode`.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AtRestMode {
    /// New writes are plaintext; sealed data is still read when keys exist.
    #[default]
    Off,
    /// New writes are sealed; legacy plaintext is still read.
    Encrypt,
    /// New writes are sealed; legacy plaintext is refused.
    Strict,
}

/// A snapshot of the node's at-rest state for one storage operation.
#[derive(Clone)]
pub struct AtRestView {
    pub mode: AtRestMode,
    /// The gate passed and the keys are unlocked: new writes are sealed.
    pub encrypting: bool,
    /// Set once the keyring is installed (locked or not).
    pub provider: Option<Arc<dyn DataKeyProvider>>,
}

impl AtRestView {
    /// The state of a node without at-rest wiring: `off`, no keys.
    pub fn off() -> Self {
        Self {
            mode: AtRestMode::Off,
            encrypting: false,
            provider: None,
        }
    }

    /// The object-name key, if keys are set up and unlocked.
    pub fn object_name_key(&self) -> Option<ObjectNameKey> {
        self.provider.as_ref()?.object_name_key().ok()
    }

    /// Whether legacy plaintext may be read (every mode but `strict`).
    pub fn legacy_readable(&self) -> bool {
        self.mode != AtRestMode::Strict
    }
}

/// Where storage reads its at-rest state from: the node's runtime, or a
/// test double.
pub trait AtRestSource: Send + Sync {
    fn view(&self) -> AtRestView;
}
