//! SSH-managed remote workspaces. Validation also runs in the server build,
//! since both runtimes share the database schema. Process/tunnel ownership is
//! desktop-only; the remote server needs no SSH capability or protocol change.
#[cfg(feature = "tauri-runtime")]
pub mod bootstrap;
#[cfg(feature = "tauri-runtime")]
pub mod command;
pub mod config;
#[cfg(feature = "tauri-runtime")]
pub mod redact;
#[cfg(feature = "tauri-runtime")]
pub mod tunnel;

#[cfg(all(
    test,
    feature = "tauri-runtime",
    feature = "test-utils",
    target_os = "linux"
))]
mod integration_tests;
