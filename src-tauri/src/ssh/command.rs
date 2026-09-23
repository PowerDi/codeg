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

/// The non-negotiable options on every `ssh` codeg spawns.
///
/// `BatchMode=yes` is what makes this safe to run from a GUI: `ssh` will never
/// prompt. No password prompt, no passphrase prompt, no "are you sure you want
/// to continue connecting" — it fails with a message instead, and we turn that
/// into an instruction to go finish the setup in a terminal. A GUI that cannot
/// answer a prompt must not be given one, or it hangs forever holding a lock.
///
/// `StrictHostKeyChecking=yes` is the other half. The tempting value here is
/// `accept-new`, which would make first connections "just work" — and would
/// also make codeg trust whatever key answers the first time, which is the one
/// moment a MITM has to be wrong. We require the host to already be in
/// `known_hosts`, and tell the user to run `ssh <host>` once themselves so they
/// see and accept the fingerprint with their own eyes.
///
/// Note these are passed as separate `-o` `KEY=VALUE` argv pairs rather than
/// `-oKEY=VALUE`; both are accepted by OpenSSH, and the split form keeps each
/// value in its own entry where it cannot be misread.
fn base_options() -> Vec<(&'static str, String)> {
    vec![
        ("BatchMode", "yes".to_string()),
        ("StrictHostKeyChecking", "yes".to_string()),
        // Belt and braces with BatchMode: even if a future OpenSSH decided
        // BatchMode permitted some interaction, there is no askpass to reach.
        ("PasswordAuthentication", "no".to_string()),
        ("KbdInteractiveAuthentication", "no".to_string()),
        ("NumberOfPasswordPrompts", "0".to_string()),
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
    let mut args: Vec<OsString> = Vec::new();

    for (key, value) in base_options() {
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
    let mut command = crate::process::tokio_command("ssh");
    command.args(build_ssh_args(config, invocation, remote_command));
    // `ssh` reads `~/.ssh/config` and talks to `ssh-agent` through the
    // environment it inherits, which is exactly what we want: the user's own
    // configuration stays authoritative. `SSH_ASKPASS` is the one thing worth
    // suppressing — with `SSH_ASKPASS_REQUIRE=never`, a GUI askpass helper can
    // never pop up behind the app where nobody would see it, and BatchMode's
    // clean failure is what the user gets instead.
    command.env("SSH_ASKPASS_REQUIRE", "never");
    command
}

/// Turn a failed `ssh` run into an error that tells the user what to *do*.
///
/// `BatchMode=yes` + `StrictHostKeyChecking=yes` mean the two most common first-
/// run failures are both "go do something in a terminal once", and neither is
/// self-evident from ssh's own wording. Anything unrecognised is passed through
/// redacted rather than reworded, because a wrong guess is worse than the raw
/// message.
pub fn classify_ssh_failure(stderr: &str, exit_code: Option<i32>) -> AppCommandError {
    let lower = stderr.to_ascii_lowercase();
    let detail =
        crate::ssh::redact::truncate_for_detail(&crate::ssh::redact::redact_secrets(stderr.trim()));

    // Host key problems first: `StrictHostKeyChecking=yes` refuses an unknown
    // host, and codeg deliberately does not accept it on the user's behalf.
    if lower.contains("host key verification failed")
        || lower.contains("no matching host key")
        || lower.contains("not known")
        || lower.contains("known_hosts")
    {
        return AppCommandError::authentication_failed(
            "The remote host is not in your known_hosts yet, so codeg refused to connect.",
        )
        .with_detail(format!(
            "Run `ssh <host>` once in a terminal, check the fingerprint, and accept it. \
             codeg never accepts an unverified host key for you.\n\n{detail}"
        ));
    }

    if lower.contains("permission denied")
        || lower.contains("no supported authentication")
        || lower.contains("too many authentication failures")
        || lower.contains("publickey")
    {
        return AppCommandError::authentication_failed("The remote host refused the SSH key.")
            .with_detail(format!(
                "codeg only uses non-interactive key authentication (no passwords, no MFA). \
             Make sure the key is loaded in ssh-agent (or set an identity file), that \
             `ssh <host>` works in a terminal without prompting, and that the key is in \
             the remote account's authorized_keys.\n\n{detail}"
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
            "The SSH key needs a passphrase, which codeg cannot prompt for.",
        )
        .with_detail(format!(
            "Load the key into ssh-agent first (`ssh-add <key>`), then reconnect. \
             Interactive password and MFA logins are not supported.\n\n{detail}"
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
