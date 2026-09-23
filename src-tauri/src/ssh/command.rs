//! Builds the argv for every `ssh` invocation codeg makes.
//!
//! One builder, used by both the bootstrap exec and the tunnel, so the security
//! options cannot drift apart between them. The options are not configurable by
//! the frontend on purpose — see [`base_options`].

use std::ffi::OsString;

use crate::app_error::AppCommandError;
use crate::models::RemoteWorkspaceSshConfig;

/// Seconds between keepalive probes on a tunnel, and the number of missed
/// probes tolerated. 15s × 3 means a dead network is noticed in ~45s, which is
/// well inside the WS layer's own reconnect patience.
const SERVER_ALIVE_INTERVAL: u32 = 15;
const SERVER_ALIVE_COUNT_MAX: u32 = 3;

/// Connect timeout for a one-shot command. Bounded so a black-holed host fails
/// instead of hanging a command worker.
const CONNECT_TIMEOUT_SECS: u32 = 20;

/// GUI authentication is enabled only with our owned askpass broker. Headless
/// tests retain strict, noninteractive key authentication. Neither mode ever
/// auto-accepts host keys, reads passwords from stdin, or joins a shared master.
fn base_options(interactive: bool) -> Vec<(&'static str, String)> {
    vec![
        ("BatchMode", if interactive { "no" } else { "yes" }.to_string()),
        ("StrictHostKeyChecking", if interactive { "ask" } else { "yes" }.to_string()),
        ("FingerprintHash", "sha256".to_string()),
        // Passwords/passphrases go only through our helper. Arbitrary remote
        // keyboard-interactive challenges cannot impersonate a cached prompt.
        ("PasswordAuthentication", if interactive { "yes" } else { "no" }.to_string()),
        ("KbdInteractiveAuthentication", "no".to_string()),
        ("NumberOfPasswordPrompts", if interactive { "1" } else { "0" }.to_string()),
        // `ssh` must not read a terminal even if one is somehow attached.
        ("RequestTTY", "no".to_string()),
        ("SessionType", "default".to_string()),
        ("StdinNull", "no".to_string()),
        ("ExitOnForwardFailure", "yes".to_string()),
        // Opt out of connection multiplexing, explicitly.
        //
        // This is not a performance choice, it is an ownership one. If the user's
        // `~/.ssh/config` sets `ControlMaster auto` (common, and a `ssh -G` probe
        // confirms it survives everything else we pass), our `ssh -L` would not
        // open its own connection at all: it would hand the forward to whatever
        // master process already exists for that host. Two consequences, both
        // bad. Killing our child would no longer close the tunnel — the master
        // keeps it, so `shutdown` silently stops working and a deleted profile
        // leaves a live forward behind. And with `ControlPersist`, a master
        // outliving the app would keep a loopback port open onto the user's
        // remote host with nothing on our side tracking it.
        //
        // `ControlMaster=no` stops us joining as a client, and `ControlPath=none`
        // is the belt to that braces: it disables multiplexing outright, so even
        // a config that sets a path cannot route us into a shared socket. Every
        // tunnel is then a process we spawned, own, and can prove we killed.
        //
        // What this costs is a fresh TCP+auth handshake per tunnel, which is
        // exactly what we want to be paying for. Routing config the user cares
        // about — `ProxyJump`, `ProxyCommand`, `User`, `Port`, `IdentityFile`,
        // `HostName` — is untouched and still read from their config.
        ("ControlMaster", "no".to_string()),
        ("ControlPath", "none".to_string()),
        ("ControlPersist", "no".to_string()),
        ("ForkAfterAuthentication", "no".to_string()),
        ("RemoteCommand", "none".to_string()),
        ("PermitLocalCommand", "no".to_string()),
        ("ForwardAgent", "no".to_string()),
        ("ForwardX11", "no".to_string()),
        ("GatewayPorts", "no".to_string()),
    ]
}

/// What the invocation is for. The two shapes differ only in forwarding and
/// timeouts, so they share everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshInvocation {
    /// A one-shot remote command: run the bootstrap, read its reply, exit.
    /// stdin carries the script, so `-T` (no pty) matters.
    Exec,
    /// A long-lived local forward: `-L 127.0.0.1:<local>:127.0.0.1:<remote>`.
    ///
    /// Both ends are pinned to loopback. The local bind address is the one that
    /// matters for safety: the default for `-L <port>:…` binds per
    /// `GatewayPorts`, and an accidental `0.0.0.0` bind would publish an
    /// authenticated codeg-server to the user's whole LAN. The remote end is
    /// loopback because that is where the remote server listens — we start it
    /// with `CODEG_HOST=127.0.0.1` so it is never reachable from the remote
    /// host's network either.
    Tunnel { local_port: u16, remote_port: u16 },
}

/// Build the full argv for an `ssh` run, *excluding* the program name.
///
/// Order is deliberate: options first, then the destination, then (for `Exec`)
/// nothing — the remote command arrives on stdin via a `sh -s` reader, so no
/// user-derived string is ever concatenated into a remote shell line here.
pub fn build_ssh_args(
    config: &RemoteWorkspaceSshConfig,
    invocation: SshInvocation,
    remote_command: Option<&str>,
) -> Vec<OsString> {
    build_ssh_args_with_interaction(config, invocation, remote_command, false)
}

fn build_ssh_args_with_interaction(
    config: &RemoteWorkspaceSshConfig,
    invocation: SshInvocation,
    remote_command: Option<&str>,
    interactive: bool,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();

    for (key, value) in base_options(interactive) {
        args.push(OsString::from("-o"));
        args.push(OsString::from(format!("{key}={value}")));
    }

    match invocation {
        SshInvocation::Exec => {
            args.extend(
                ["-o", "ClearAllForwardings=yes", "-o", "StdinNull=no"]
                    .into_iter()
                    .map(OsString::from),
            );
            args.push(OsString::from("-o"));
            args.push(OsString::from(format!(
                "ConnectTimeout={CONNECT_TIMEOUT_SECS}"
            )));
            // No pty: the bootstrap script is fed on stdin and its reply is
            // parsed from stdout. A pty would merge stderr into stdout and
            // mangle both with terminal control sequences.
            args.push(OsString::from("-T"));
        }
        SshInvocation::Tunnel {
            local_port,
            remote_port,
        } => {
            args.push(OsString::from("-o"));
            args.push(OsString::from(format!(
                "ServerAliveInterval={SERVER_ALIVE_INTERVAL}"
            )));
            args.push(OsString::from("-o"));
            args.push(OsString::from(format!(
                "ServerAliveCountMax={SERVER_ALIVE_COUNT_MAX}"
            )));
            args.push(OsString::from("-o"));
            args.push(OsString::from(format!(
                "ConnectTimeout={CONNECT_TIMEOUT_SECS}"
            )));
            // A tiny remote command acknowledges forwarding setup, then
            // waits for stdin EOF. Do not use -N: that would suppress its ack.
            args.extend(["-o", "ClearAllForwardings=no"].into_iter().map(OsString::from));
            args.push(OsString::from("-T"));
            args.push(OsString::from("-L"));
            args.push(OsString::from(format!(
                "127.0.0.1:{local_port}:127.0.0.1:{remote_port}"
            )));
        }
    }

    if let Some(port) = config.port {
        args.push(OsString::from("-p"));
        args.push(OsString::from(port.to_string()));
    }
    if let Some(identity_file) = &config.identity_file {
        args.push(OsString::from("-i"));
        args.push(OsString::from(identity_file));
    }
    if let Some(username) = &config.username {
        // `-l user` rather than `user@host`: the host stays a standalone token,
        // so a `~/.ssh/config` alias lookup still matches it exactly.
        args.push(OsString::from("-l"));
        args.push(OsString::from(username));
    }

    // `--` terminates option parsing. Combined with the leading-`-` rejection in
    // `ssh::config`, the destination cannot be read as an option even if a
    // future validator relaxes.
    args.push(OsString::from("--"));
    args.push(OsString::from(&config.host));

    if let Some(command) = remote_command {
        args.push(OsString::from(command));
    }

    args
}

/// A ready-to-spawn `ssh` command for this locator and invocation.
///
/// Goes through `crate::process::tokio_command`, which is what applies the
/// repo-wide Windows convention of `CREATE_NO_WINDOW` — without it every tunnel
/// and every bootstrap would flash a console window on the user's desktop.
///
/// Callers set their own stdio and `kill_on_drop`; this only builds the argv.
pub fn ssh_command(
    config: &RemoteWorkspaceSshConfig,
    invocation: SshInvocation,
    remote_command: Option<&str>,
) -> tokio::process::Command {
    ssh_command_with_askpass(config, invocation, remote_command, None)
}

pub fn ssh_command_with_askpass(
    config: &RemoteWorkspaceSshConfig,
    invocation: SshInvocation,
    remote_command: Option<&str>,
    askpass: Option<&crate::ssh::askpass::AskpassServer>,
) -> tokio::process::Command {
    let mut command = crate::process::tokio_command("ssh");
    command.args(build_ssh_args_with_interaction(config, invocation, remote_command, askpass.is_some()));
    command.env("SSH_ASKPASS_REQUIRE", "never");
    if let Some(askpass) = askpass { askpass.apply(&mut command); }
    command
}

/// Turn a failed `ssh` run into an error that tells the user what to *do*.
///
/// Distinguish host trust, rejected credentials and transport failures. Both
/// GUI askpass and batch-mode tests use this mapping. Anything unrecognised is passed through
/// redacted rather than reworded, because a wrong guess is worse than the raw
/// message.
pub fn classify_ssh_failure(stderr: &str, exit_code: Option<i32>) -> AppCommandError {
    let lower = stderr.to_ascii_lowercase();
    let detail =
        crate::ssh::redact::truncate_for_detail(&crate::ssh::redact::redact_secrets(stderr.trim()));

    if lower.contains("remote host identification has changed") {
        return AppCommandError::authentication_failed("The SSH host key has changed; connection refused")
            .with_detail(format!("Verify the new fingerprint through a trusted channel before updating known_hosts. Codeg will not bypass a changed host key.\n\n{detail}"));
    }

    // Host key problems first: `StrictHostKeyChecking=yes` refuses an unknown
    // host, and codeg deliberately does not accept it on the user's behalf.
    if lower.contains("host key verification failed")
        || lower.contains("no matching host key")
        || lower.contains("not known")
        || lower.contains("known_hosts")
    {
        return AppCommandError::authentication_failed(
            "The SSH host key could not be verified, so codeg refused to connect.",
        )
        .with_detail(format!(
            "Confirm the fingerprint in Codeg (or with `ssh <host>` in a terminal). \
             Codeg never accepts an unverified or changed host key for you.\n\n{detail}"
        ));
    }

    if lower.contains("permission denied")
        || lower.contains("no supported authentication")
        || lower.contains("too many authentication failures")
        || lower.contains("publickey")
    {
        return AppCommandError::authentication_failed("The remote host refused SSH authentication.")
            .with_detail(format!(
                "Check the username and password, or use an authorized key / ssh-agent. \
             The server must allow password or public-key authentication. \
             Keyboard-interactive MFA is not supported.\n\n{detail}"
            ));
    }

    if lower.contains("connection timed out")
        || lower.contains("connection refused")
        || lower.contains("could not resolve hostname")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
    {
        return AppCommandError::network("Could not reach the remote host over SSH.")
            .with_detail(detail);
    }

    if lower.contains("passphrase") || lower.contains("password") {
        return AppCommandError::authentication_failed(
            "SSH authentication needs a password or key passphrase.",
        )
        .with_detail(format!(
            "Reconnect and answer the authentication dialog, or load the key into ssh-agent. \
             Keyboard-interactive MFA is not supported.\n\n{detail}"
        ));
    }

    AppCommandError::network(match exit_code {
        Some(code) => format!("The ssh client exited with status {code}."),
        None => "The ssh client was terminated before it could connect.".to_string(),
    })
    .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn cfg() -> RemoteWorkspaceSshConfig {
        RemoteWorkspaceSshConfig {
            host: "build-box".into(),
            ..Default::default()
        }
    }

    /// If either of these ever stops being passed, codeg starts either hanging
    /// on an unanswerable prompt or trusting unverified host keys.
    #[test]
    fn gui_authentication_keeps_host_verification_and_owned_processes() {
        let config = RemoteWorkspaceSshConfig { host: "server".into(), ..Default::default() };
        let args: Vec<String> = build_ssh_args_with_interaction(&config, SshInvocation::Exec, Some("true"), true)
            .iter().map(|value| value.to_string_lossy().into_owned()).collect();
        for expected in ["BatchMode=no", "StrictHostKeyChecking=ask", "FingerprintHash=sha256", "PasswordAuthentication=yes", "NumberOfPasswordPrompts=1", "KbdInteractiveAuthentication=no", "ControlMaster=no", "ControlPath=none"] {
            assert_eq!(args.iter().filter(|value| value.as_str() == expected).count(), 1);
        }
        assert!(!args.contains(&"BatchMode=yes".into()));
        assert!(!args.contains(&"StrictHostKeyChecking=no".into()));
    }

    #[test]
    fn every_invocation_sets_batchmode_and_strict_host_key_checking() {
        for invocation in [
            SshInvocation::Exec,
            SshInvocation::Tunnel {
                local_port: 51000,
                remote_port: 3080,
            },
        ] {
            let args = strings(&build_ssh_args(&cfg(), invocation, None));
            assert!(
                args.contains(&"BatchMode=yes".to_string()),
                "missing BatchMode in {args:?}"
            );
            assert!(
                args.contains(&"StrictHostKeyChecking=yes".to_string()),
                "missing StrictHostKeyChecking in {args:?}"
            );
            assert!(
                args.contains(&"PasswordAuthentication=no".to_string()),
                "missing PasswordAuthentication in {args:?}"
            );
            assert!(
                !args.iter().any(|a| a.contains("accept-new")),
                "host key checking must not be relaxed: {args:?}"
            );
        }
    }

    /// Both ends of the forward must be loopback-pinned. A bare `-L 51000:…`
    /// would bind per `GatewayPorts` and could expose the tunnel to the LAN.
    #[test]
    fn tunnel_binds_both_ends_to_loopback() {
        let args = strings(&build_ssh_args(
            &cfg(),
            SshInvocation::Tunnel {
                local_port: 51000,
                remote_port: 3080,
            },
            None,
        ));
        let forward = args
            .iter()
            .position(|a| a == "-L")
            .map(|i| args[i + 1].clone())
            .expect("-L present");
        assert_eq!(forward, "127.0.0.1:51000:127.0.0.1:3080");
        assert!(!args.contains(&"-N".to_string()));
        assert!(args.contains(&"ClearAllForwardings=no".to_string()));
        assert!(args.contains(&"StdinNull=no".to_string()));
        assert!(args.contains(&"ExitOnForwardFailure=yes".to_string()));
    }

    #[test]
    fn exec_uses_no_pty_and_a_connect_timeout() {
        let args = strings(&build_ssh_args(&cfg(), SshInvocation::Exec, None));
        assert!(args.contains(&"-T".to_string()));
        assert!(args.iter().any(|a| a.starts_with("ConnectTimeout=")));
        assert!(
            !args.contains(&"-N".to_string()),
            "an exec run must be allowed to carry a command"
        );
    }

    /// Unset optionals must contribute no flags at all, so `~/.ssh/config`
    /// remains authoritative for user, port and key.
    #[test]
    fn omits_user_port_and_key_flags_when_unset() {
        let args = strings(&build_ssh_args(&cfg(), SshInvocation::Exec, None));
        for flag in ["-p", "-i", "-l"] {
            assert!(
                !args.contains(&flag.to_string()),
                "{flag} must be absent when unset: {args:?}"
            );
        }
    }

    #[test]
    fn passes_user_port_and_key_as_separate_argv_entries() {
        let config = RemoteWorkspaceSshConfig {
            host: "build-box".into(),
            username: Some("ann".into()),
            port: Some(2222),
            identity_file: Some(r"C:\Users\Ann Smith\.ssh\id_ed25519".into()),
        };
        let args = strings(&build_ssh_args(&config, SshInvocation::Exec, None));

        let after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .map(|i| args[i + 1].clone())
                .unwrap_or_else(|| panic!("{flag} missing from {args:?}"))
        };
        assert_eq!(after("-p"), "2222");
        assert_eq!(after("-l"), "ann");
        // One entry, spaces intact: no quoting needed, and none applied.
        assert_eq!(after("-i"), r"C:\Users\Ann Smith\.ssh\id_ed25519");
    }

    /// The destination is the last thing before any remote command, and it is
    /// preceded by `--`. Together with validation this is belt-and-braces
    /// against a hostname being re-read as an option.
    #[test]
    fn destination_follows_a_double_dash_terminator() {
        let args = strings(&build_ssh_args(&cfg(), SshInvocation::Exec, None));
        let dashdash = args
            .iter()
            .position(|a| a == "--")
            .expect("-- terminator present");
        assert_eq!(args[dashdash + 1], "build-box");
        assert_eq!(dashdash + 2, args.len(), "host is the final argument");
    }

    /// The username goes through `-l`, never glued into `user@host`: an alias
    /// lookup in `~/.ssh/config` matches the bare host token.
    #[test]
    fn never_builds_a_user_at_host_destination() {
        let config = RemoteWorkspaceSshConfig {
            host: "build-box".into(),
            username: Some("ann".into()),
            ..Default::default()
        };
        let args = strings(&build_ssh_args(&config, SshInvocation::Exec, None));
        assert!(
            !args.iter().any(|a| a.contains('@')),
            "destination must stay a bare host: {args:?}"
        );
    }

    #[test]
    fn remote_command_lands_after_the_destination() {
        let args = strings(&build_ssh_args(
            &cfg(),
            SshInvocation::Exec,
            Some("sh -s -- bootstrap"),
        ));
        assert_eq!(args.last().unwrap(), "sh -s -- bootstrap");
        assert_eq!(args[args.len() - 2], "build-box");
    }
}
