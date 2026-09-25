use chrono::{DateTime, Utc};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkspaceHeader {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

impl RemoteWorkspaceHeader {
    pub fn to_header_pair(&self) -> Result<(HeaderName, HeaderValue), http::Error> {
        let name: HeaderName = self.name.trim().try_into()?;
        let mut value: HeaderValue = self.value.trim().try_into()?;
        // A custom header on a remote connection normally carries a credential
        // (a Cloudflare Access service token, a proxy secret), so it gets the
        // same treatment `reqwest` gives its own `bearer_auth` value: never
        // added to the HTTP/2 HPACK dynamic table, and redacted from `Debug`.
        value.set_sensitive(true);
        Ok((name, value))
    }
}

pub trait ToHeaderMap {
    fn to_header_map(&self) -> HeaderMap;
}

impl ToHeaderMap for [RemoteWorkspaceHeader] {
    fn to_header_map(&self) -> HeaderMap {
        self.iter()
            .filter_map(|header| header.to_header_pair().ok())
            .collect()
    }
}

/// An SSH-managed remote workspace: instead of an operator-supplied URL and
/// token, codeg reaches the remote host over the system `ssh` client, installs
/// (or reuses) an upstream `codeg-server` release there, and forwards a
/// loopback port to it.
///
/// Only the *locator* is persisted. Nothing here is a credential: the key is
/// referenced by path, never by content, and the server token is minted on the
/// remote host and re-read over the encrypted channel on every connect. A
/// profile is therefore safe to back up, and a rotated token or a re-picked
/// port needs no edit here.
///
/// `None` on the optional fields means "whatever the user's own SSH
/// configuration already says" — `~/.ssh/config` stays authoritative, so a
/// `Host` alias with its own `User`/`Port`/`IdentityFile` keeps working. That is
/// why `port` is not defaulted to 22: writing 22 here would silently override a
/// config that says otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteWorkspaceSshConfig {
    /// Hostname, IP, or a `Host` alias from the user's `~/.ssh/config`.
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Path to a private key. The path only — the key never enters the
    /// database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// The password itself lives in the OS credential store. This flag is the
    /// only credential-related value persisted with the connection profile.
    #[serde(default, skip_serializing_if = "is_false")]
    pub remember_password: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteWorkspaceConnectionInfo {
    pub id: i32,
    pub name: String,
    /// HTTP URL, or a display-only `ssh://host` for an SSH profile. A live
    /// SSH endpoint is resolved by the desktop proxy and is never persisted.
    pub base_url: String,
    /// Empty for SSH profiles. The runtime token stays in the Rust process.
    pub token: String,
    #[serde(default)]
    pub headers: Vec<RemoteWorkspaceHeader>,
    /// `None` for a plain HTTP connection — the original behaviour, and what
    /// every row written before this column existed deserializes to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<RemoteWorkspaceSshConfig>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RemoteWorkspaceConnectionInfo {
    /// True when this connection is reached over SSH rather than a
    /// user-supplied URL.
    pub fn is_ssh(&self) -> bool {
        self.ssh.is_some()
    }
}
