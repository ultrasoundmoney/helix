//! The merge engine, exposed as a library.
//!
//! `helix-builder` is a binary crate whose merging logic is wrapped in a
//! transport layer built on `flux`. We want the merging logic and none of the
//! transport: our relay drives the engine over its own connection, and the
//! engine itself is transport-agnostic — it consumes `EngineEvent` and emits
//! `EngineOutput` over plain channels.
//!
//! Rather than copy those files, this crate re-exports them in place with
//! `#[path]`. Nothing upstream is edited, so merging from `gattaca-com/helix`
//! stays conflict-free and we keep receiving fixes to the merging logic — which
//! is young and still changing. `helix-builder` continues to build and run
//! unaffected; we simply do not use it.
//!
//! Deliberately excluded: `main.rs`, `spine.rs` and `server/`, which are the
//! only modules that depend on `flux`.

// `ReplayCheckpoint` is `pub(crate)` upstream but reachable through a `pub`
// field. Allowed here rather than patched there, to keep upstream files clean.
#![allow(private_interfaces)]

#[path = "../../builder/src/engine/mod.rs"]
pub mod engine;

/// Ethrex node bootstrap and `HeadInfo`, which the engine needs for chain state.
#[path = "../../builder/src/node.rs"]
pub mod node;

/// `NodeOptions`, required by [`node`].
#[path = "../../builder/src/cli.rs"]
pub mod cli;

/// `utcnow_ns`, used throughout the engine.
#[path = "../../builder/src/utils.rs"]
pub mod utils;

/// The engine's prometheus counters and timings.
#[path = "../../builder/src/metrics.rs"]
pub mod metrics;

#[path = "../../builder/src/validation/error.rs"]
mod validation_error;

/// Only `ValidationError`, which the engine's payload conversion returns.
pub mod validation {
    pub mod error {
        pub use crate::validation_error::*;
    }
}

/// Shared with the builder's other roles, whose helpers go unused here.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../builder/src/testing.rs"]
mod testing;
