//! Remote bootstrap: install-or-reuse an upstream `codeg-server` over SSH and
//! learn the loopback port and token it is listening with.
//!
//! The remote half is [`BOOTSTRAP_SCRIPT`], piped to `sh -s` on stdin. Nothing
//! is written to the remote filesystem to run it, and nothing is fetched from
//! the network to run it — which is the difference between this and a
//! `curl | sh` install.
//!
//! The script answers with a single sentinel line carrying JSON. Everything
//! else it writes is diagnostics, because a login shell will happily prepend a
//! banner, a MOTD, or an rc-file warning to any command's output; scanning for
//! the sentinel is what makes this robust against that.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::app_error::AppCommandError;
use crate::models::RemoteWorkspaceSshConfig;
use crate::ssh::command::{ssh_command_with_askpass, SshInvocation};
use crate::ssh::redact::redact_secrets;

/// The remote script. Compiled in, so the desktop binary is self-contained and
/// the remote host never has to trust a download to bootstrap.
pub const BOOTSTRAP_SCRIPT: &str = include_str!("bootstrap.sh");

/// Sentinel prefix for the script's one machine-readable line. MUST match
/// `SENTINEL` in `bootstrap.sh`.
const RESULT_SENTINEL: &str = "CODEG_BOOTSTRAP_RESULT ";

pub type BootstrapProgress = Arc<dyn Fn(String) + Send + Sync>;

/// Fixed upstream release source. Not configurable, and deliberately not
/// reachable from the frontend: a settable download base would turn "add a
/// remote workspace" into "run this attacker's binary on your server".
const RELEASE_BASE: &str = "https://github.com/xintaofei/codeg/releases/download";

/// Directory under the remote user's `$HOME` that owns everything this feature
/// creates. Distinct from `~/.codeg`, which is where a manually installed
/// server keeps its data — an SSH workspace must not adopt or migrate that.
const REMOTE_ROOT_NAME: &str = ".codeg-ssh-workspace";

/// Loopback port range the remote server is placed in. High, ephemeral-adjacent
/// range to stay clear of anything the user runs deliberately.
const PORT_MIN: u16 = 42000;
const PORT_MAX: u16 = 42999;

/// How many ports to try before giving up, and how long to wait for each
/// attempt to answer a health check.
const START_ATTEMPTS: u32 = 5;
const READY_TIMEOUT_SECS: u32 = 40;

/// How long the remote script waits on the bootstrap `flock` before giving up.
/// Must comfortably exceed a cold install (download + first start) so a second
/// window opening the same workspace waits for the first rather than failing;
/// still bounded, so a wedged holder cannot block forever.
const LOCK_WAIT_SECS: u32 = 300;

/// Ceiling on the whole bootstrap. Generous: a cold run downloads ~40 MB and
/// starts a server, and a first connect is documented as possibly taking
/// minutes. Bounded all the same, so a wedged remote cannot hang a command
/// worker forever.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(600);

/// What the remote script reports on success.
#[derive(Clone)]
pub struct BootstrapOutcome {
    /// Loopback port on the *remote* host. Only reachable through the tunnel.
    pub port: u16,
    /// Bearer token minted on the remote host.
    pub token: String,
    /// Version actually serving. Not necessarily the requested one: an already
    /// running instance is reused rather than replaced.
    pub version: String,
    /// True when an existing background instance was adopted.
    pub reused: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum BootstrapReply {
    Ok {
        port: u16,
        token: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        reused: bool,
    },
    Error {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    },
}

/// Turn a machine-readable failure code from the script into a message that
/// tells the user what to do, not merely what broke.
fn error_for_code(code: &str, message: &str) -> AppCommandError {
    let fallback = if message.is_empty() {
        "The remote bootstrap failed."
    } else {
        message
    };
    match code {
        "unsupported_os" | "unsupported_arch" | "unsupported_libc" => {
            AppCommandError::configuration_invalid(fallback.to_string())
        }
        "missing_curl" | "missing_tar" | "missing_sha256" => AppCommandError::new(
            crate::app_error::AppErrorCode::DependencyMissing,
            fallback.to_string(),
        ),
        "checksum_mismatch"
        | "checksum_malformed"
        | "checksum_unavailable"
        | "incomplete_archive" => AppCommandError::configuration_invalid(fallback.to_string())
            .with_detail("The remote install was aborted before anything was executed."),
        "download_failed" => AppCommandError::network(fallback.to_string()).with_detail(
            "The remote host needs outbound HTTPS access to github.com to install codeg-server.",
        ),
        "lock_timeout" => AppCommandError::new(
            crate::app_error::AppErrorCode::TaskExecutionFailed,
            fallback.to_string(),
        ),
        _ => AppCommandError::new(
            crate::app_error::AppErrorCode::TaskExecutionFailed,
            fallback.to_string(),
        ),
    }
}

/// Extract the reply from the script's stdout.
///
/// Scans for the sentinel and takes the **last** occurrence, so a banner that
/// happens to echo an earlier line cannot shadow the real answer.
fn parse_reply(stdout: &str) -> Result<BootstrapOutcome, AppCommandError> {
    let payload = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix(RESULT_SENTINEL))
        .next_back()
        .ok_or_else(|| {
            AppCommandError::new(
                crate::app_error::AppErrorCode::TaskExecutionFailed,
                "The remote host did not return a usable bootstrap result.",
            )
            .with_detail(
                "The SSH session produced no result line. This usually means the remote \
                 login shell failed before the bootstrap could run.",
            )
        })?;

    let reply: BootstrapReply = serde_json::from_str(payload.trim()).map_err(|e| {
        // The payload can carry the token, so the parse error is described
        // without quoting it.
        AppCommandError::new(
            crate::app_error::AppErrorCode::TaskExecutionFailed,
            "The remote bootstrap result could not be parsed.",
        )
        .with_detail(format!(
            "Invalid JSON at line {}, column {}",
            e.line(),
            e.column()
        ))
    })?;

    match reply {
        BootstrapReply::Ok {
            port,
            token,
            version,
            reused,
        } => {
            let token = token.trim().to_string();
            if port == 0 || token.is_empty() {
                return Err(AppCommandError::new(
                    crate::app_error::AppErrorCode::TaskExecutionFailed,
                    "The remote bootstrap returned an incomplete result.",
                ));
            }
            Ok(BootstrapOutcome {
                port,
                token,
                version,
                reused,
            })
        }
        BootstrapReply::Error { code, message } => Err(error_for_code(
            &code,
            &crate::ssh::redact::truncate_for_detail(&redact_secrets(&message)),
        )),
    }
}

/// The prelude of `KEY=value` assignments prepended to the script.
///
/// Every value is a constant or an integer from this module — no user input
/// reaches the remote shell, which is why plain assignment is safe here and why
/// there is no remote quoting problem to solve.
fn script_prelude(version: &str) -> String {
    format!(
        "CODEG_REMOTE_VERSION={version}\n\
         CODEG_REMOTE_ROOT_NAME={REMOTE_ROOT_NAME}\n\
         CODEG_REMOTE_RELEASE_BASE={RELEASE_BASE}\n\
         CODEG_REMOTE_PORT_MIN={PORT_MIN}\n\
         CODEG_REMOTE_PORT_MAX={PORT_MAX}\n\
         CODEG_REMOTE_START_ATTEMPTS={START_ATTEMPTS}\n\
         CODEG_REMOTE_READY_TIMEOUT={READY_TIMEOUT_SECS}\n\
         CODEG_REMOTE_LOCK_WAIT={LOCK_WAIT_SECS}\n\
         export CODEG_REMOTE_VERSION CODEG_REMOTE_ROOT_NAME CODEG_REMOTE_RELEASE_BASE \
         CODEG_REMOTE_PORT_MIN CODEG_REMOTE_PORT_MAX CODEG_REMOTE_START_ATTEMPTS \
         CODEG_REMOTE_READY_TIMEOUT CODEG_REMOTE_LOCK_WAIT\n"
    )
}

/// The desktop app's own version, which is the release the remote is asked to
/// install. Keeping the two in step means the API the proxy speaks is the API
/// the remote serves.
fn requested_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Full remote payload: prelude, then the script.
pub fn bootstrap_payload(version: &str) -> String {
    payload_with_script(version, BOOTSTRAP_SCRIPT)
}

fn payload_with_script(version: &str, script: &str) -> String {
    // A Windows source checkout may use CRLF. The payload is executed by a
    // Linux shell, where a carriage return becomes part of the command/argv.
    format!(
        "{}{}",
        script_prelude(version),
        script.replace("\r\n", "\n")
    )
}

/// Run the bootstrap on `locator`'s host.
///
/// Reuses a healthy background instance when one exists; otherwise installs the
/// pinned release (verifying its published checksum first) and starts it bound
/// to remote loopback.
pub async fn run_bootstrap(
    config: &RemoteWorkspaceSshConfig,
) -> Result<BootstrapOutcome, AppCommandError> {
    run_bootstrap_with_askpass(config, None).await
}

pub async fn run_bootstrap_with_askpass(
    config: &RemoteWorkspaceSshConfig,
    askpass: Option<&crate::ssh::askpass::AskpassServer>,
) -> Result<BootstrapOutcome, AppCommandError> {
    run_bootstrap_with_askpass_and_progress(config, askpass, None).await
}

pub async fn run_bootstrap_with_askpass_and_progress(
    config: &RemoteWorkspaceSshConfig,
    askpass: Option<&crate::ssh::askpass::AskpassServer>,
    progress: Option<&BootstrapProgress>,
) -> Result<BootstrapOutcome, AppCommandError> {
    // `sh -s` reads the program from stdin. The remote argv therefore carries no
    // user data and no script text at all.
    let mut command = ssh_command_with_askpass(config, SshInvocation::Exec, Some("sh -s"), askpass);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Any early return past this point must not leave an ssh client behind.
        .kill_on_drop(true);

    let payload = bootstrap_payload(requested_version());
    let output = bounded_ssh_output(
        command,
        payload.as_bytes(),
        BOOTSTRAP_TIMEOUT,
        progress.cloned(),
    )
    .await;
    if let Some(error) = askpass.and_then(|auth| auth.failure()) {
        return Err(error);
    }
    let output = output?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = askpass.map_or_else(|| stderr.to_string(), |auth| auth.redact(&stderr));

    if !output.status.success() && !stdout.contains(RESULT_SENTINEL) {
        return Err(crate::ssh::command::classify_ssh_failure(
            &stderr,
            output.status.code(),
        ));
    }

    let outcome = parse_reply(&stdout).map_err(|err| {
        // Attach the remote diagnostics, redacted. The server's own stderr is
        // never included by the script for exactly this reason, but the
        // redaction is applied unconditionally — it is cheap, and the whole
        // point is not to rely on the other side having been careful.
        let trimmed = stderr.trim();
        if trimmed.is_empty() || err.detail.is_some() {
            err
        } else {
            err.with_detail(crate::ssh::redact::truncate_for_detail(&redact_secrets(
                trimmed,
            )))
        }
    })?;
    Ok(outcome)
}

const OUTPUT_LIMIT: u64 = 256 * 1024;

async fn read_bounded(reader: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err(std::io::Error::other(
            "SSH output exceeded the 256 KiB safety limit",
        ));
    }
    Ok(bytes)
}

fn bootstrap_progress_message(line: &[u8]) -> Option<String> {
    let line = String::from_utf8_lossy(line);
    let message = line.trim().strip_prefix("[codeg-bootstrap] ")?.trim();
    if message.is_empty() {
        return None;
    }
    Some(crate::ssh::redact::truncate_for_detail(&redact_secrets(
        message,
    )))
}

async fn read_bounded_with_progress(
    reader: impl AsyncRead + Unpin,
    progress: Option<BootstrapProgress>,
) -> std::io::Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    loop {
        let start = bytes.len();
        let read = reader.read_until(b'\n', &mut bytes).await?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 > OUTPUT_LIMIT {
            return Err(std::io::Error::other(
                "SSH output exceeded the 256 KiB safety limit",
            ));
        }
        if let (Some(report), Some(message)) =
            (progress.as_ref(), bootstrap_progress_message(&bytes[start..]))
        {
            report(message);
        }
    }
    Ok(bytes)
}

/// Read both pipes while writing stdin. The deadline covers *all* of it,
/// including a blocked stdin write; cancellation drops the owned SSH child.
async fn bounded_ssh_output(
    mut command: tokio::process::Command,
    payload: &[u8],
    deadline: Duration,
    progress: Option<BootstrapProgress>,
) -> Result<std::process::Output, AppCommandError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppCommandError::new(
                crate::app_error::AppErrorCode::DependencyMissing,
                "The system ssh client was not found. Install OpenSSH Client and put ssh on PATH.",
            )
        } else {
            AppCommandError::io_error("Could not start the ssh client").with_detail(e.to_string())
        }
    })?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let write = async {
        // SSH may exit early on auth/host-key failure. Preserve its diagnostics
        // instead of replacing them with a broken-pipe error.
        let _ = stdin.write_all(payload).await;
        drop(stdin);
        Ok::<_, std::io::Error>(())
    };
    let operation = async {
        let (status, (), stdout, stderr) = tokio::try_join!(
            child.wait(),
            write,
            read_bounded(stdout),
            read_bounded_with_progress(stderr, progress)
        )?;
        Ok::<_, std::io::Error>(std::process::Output {
            status,
            stdout,
            stderr,
        })
    };
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| {
            AppCommandError::task_execution_failed("The remote bootstrap timed out")
                .with_detail(format!("No result after {} seconds", deadline.as_secs()))
        })?
        .map_err(|e| AppCommandError::io_error("The ssh client failed").with_detail(e.to_string()))
}

impl std::fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOutcome")
            .field("port", &self.port)
            .field("token", &"[redacted]")
            .field("version", &self.version)
            .field("reused", &self.reused)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_checkout_line_endings_never_reach_the_remote_shell() {
        assert_eq!(
            payload_with_script("0.31.2", "set -u\r\necho ok\r\n"),
            payload_with_script("0.31.2", "set -u\necho ok\n"),
        );
        assert!(!bootstrap_payload("0.31.2").contains('\r'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_also_covers_a_blocked_stdin_write() {
        let mut command = crate::process::tokio_command("sh");
        command.args(["-c", "exec sleep 30"]);
        let payload = vec![b'x'; 1024 * 1024];
        let err = bounded_ssh_output(command, &payload, Duration::from_millis(100), None)
            .await
            .unwrap_err();
        assert!(err.message.contains("timed out"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn excessive_remote_output_is_bounded() {
        let mut command = crate::process::tokio_command("sh");
        command.args(["-c", "head -c 300000 /dev/zero"]);
        let err = bounded_ssh_output(command, &[], Duration::from_secs(3), None)
            .await
            .unwrap_err();
        assert!(err.detail.unwrap().contains("safety limit"));
    }

    #[test]
    fn outcome_debug_never_contains_the_token() {
        let outcome = BootstrapOutcome {
            port: 42000,
            token: "secret-value".into(),
            version: "0.31.2".into(),
            reused: false,
        };
        assert!(!format!("{outcome:?}").contains("secret-value"));
    }

    #[test]
    fn only_controlled_bootstrap_lines_become_progress() {
        assert_eq!(
            bootstrap_progress_message(b"[codeg-bootstrap] checksum verified\n"),
            Some("checksum verified".to_string())
        );
        assert_eq!(bootstrap_progress_message(b"OpenSSH debug output\n"), None);
        assert_eq!(
            bootstrap_progress_message(b"[codeg-bootstrap] [server] token: secret-value\n"),
            Some("[server] token: [redacted]".to_string())
        );
    }

    #[test]
    fn bootstrap_imports_login_path_before_starting_the_server() {
        let import = BOOTSTRAP_SCRIPT
            .find("CODEG_LOGIN_PATH")
            .expect("login PATH import is present");
        let start = BOOTSTRAP_SCRIPT
            .find("nohup \"$SERVER_BIN\"")
            .expect("server launch is present");
        assert!(import < start, "PATH must be imported before server launch");
        assert!(BOOTSTRAP_SCRIPT.contains("timeout 5 \"$LOGIN_SHELL\" -lic"));
    }

    #[test]
    fn parses_a_fresh_start_reply() {
        let out = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":42123,\
             \"token\":\"abc123\",\"version\":\"0.31.2\",\"reused\":false}",
        )
        .unwrap();
        assert_eq!(out.port, 42123);
        assert_eq!(out.token, "abc123");
        assert_eq!(out.version, "0.31.2");
        assert!(!out.reused);
    }

    /// A login shell is free to print a banner, an rc warning, or a MOTD before
    /// our output. The parser must find the sentinel among that noise rather
    /// than assuming it owns stdout.
    #[test]
    fn ignores_login_banners_and_other_stdout_noise() {
        let out = parse_reply(
            "Welcome to Ubuntu 22.04.3 LTS\n\
             * Support: https://ubuntu.com/pro\n\
             Last login: Mon Sep 22 11:02:11 2025\n\
             CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":42999,\"token\":\"t\",\
             \"version\":\"0.31.2\",\"reused\":true}\n",
        )
        .unwrap();
        assert_eq!(out.port, 42999);
        assert!(out.reused);
    }

    /// If anything ever echoes an earlier result line back, the real answer is
    /// the last one written.
    #[test]
    fn takes_the_last_sentinel_line() {
        let out = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":1111,\"token\":\"a\",\
             \"version\":\"0.1.0\",\"reused\":false}\n\
             CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":2222,\"token\":\"b\",\
             \"version\":\"0.2.0\",\"reused\":false}\n",
        )
        .unwrap();
        assert_eq!(out.port, 2222);
    }

    #[test]
    fn missing_sentinel_is_an_error_not_a_panic() {
        let err = parse_reply("bash: line 1: sh: command not found\n").unwrap_err();
        assert!(err.message.contains("bootstrap result"));
    }

    #[test]
    fn structured_errors_map_to_actionable_codes() {
        use crate::app_error::AppErrorCode;

        let cases = [
            ("unsupported_arch", AppErrorCode::ConfigurationInvalid),
            ("unsupported_libc", AppErrorCode::ConfigurationInvalid),
            ("missing_curl", AppErrorCode::DependencyMissing),
            ("missing_sha256", AppErrorCode::DependencyMissing),
            ("checksum_mismatch", AppErrorCode::ConfigurationInvalid),
            ("download_failed", AppErrorCode::NetworkError),
            ("start_failed", AppErrorCode::TaskExecutionFailed),
        ];
        for (code, expected) in cases {
            let json = format!(
                "CODEG_BOOTSTRAP_RESULT {{\"status\":\"error\",\"code\":\"{code}\",\
                 \"message\":\"boom\"}}"
            );
            let err = parse_reply(&json).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&err.code),
                std::mem::discriminant(&expected),
                "wrong code mapping for {code}"
            );
            assert_eq!(err.message, "boom");
        }
    }

    #[test]
    fn a_reply_without_a_token_is_rejected() {
        let err = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":42000,\"token\":\"  \",\
             \"version\":\"0.31.2\",\"reused\":false}",
        )
        .unwrap_err();
        assert!(err.message.contains("incomplete"));
    }

    #[test]
    fn a_reply_with_port_zero_is_rejected() {
        let err = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":0,\"token\":\"t\",\
             \"version\":\"0.31.2\",\"reused\":false}",
        )
        .unwrap_err();
        assert!(err.message.contains("incomplete"));
    }

    /// The prelude is what the remote shell evaluates before the script. If a
    /// value ever stopped being a constant, this is the test that would notice:
    /// nothing in it may contain a shell metacharacter or a newline mid-value.
    #[test]
    fn prelude_assignments_carry_no_shell_metacharacters() {
        let prelude = script_prelude(requested_version());
        for line in prelude.lines() {
            let Some((_, value)) = line.split_once('=') else {
                assert!(
                    line.starts_with("export "),
                    "unexpected prelude line: {line}"
                );
                continue;
            };
            assert!(
                !value.contains(|c: char| "`$;&|<>(){}'\"\\".contains(c)),
                "prelude value must be a bare literal: {line}"
            );
        }
    }

    /// The release base is pinned to the upstream repository. A frontend-settable
    /// download URL would make this feature a remote-code-execution vector, so
    /// the constant is asserted rather than merely commented.
    #[test]
    fn release_base_is_pinned_to_upstream_over_https() {
        assert!(RELEASE_BASE.starts_with("https://github.com/xintaofei/codeg/"));
    }

    /// The data directory must not collide with `~/.codeg`, which is what a
    /// manually installed server on the same host uses.
    #[test]
    fn remote_root_is_isolated_from_a_manual_install() {
        assert_ne!(REMOTE_ROOT_NAME, ".codeg");
        assert!(REMOTE_ROOT_NAME.starts_with('.'));
    }

    /// The payload must be the prelude followed by the script, with the shebang
    /// comment intact — `sh -s` reads this from stdin, so a missing newline
    /// between the two halves would fuse an assignment onto a comment line.
    #[test]
    fn payload_puts_the_prelude_before_the_script() {
        let payload = bootstrap_payload("9.9.9");
        assert!(payload.starts_with("CODEG_REMOTE_VERSION=9.9.9\n"));
        assert!(payload.contains("CODEG_BOOTSTRAP_RESULT"));
        let prelude_len = script_prelude("9.9.9").len();
        assert_eq!(&payload[prelude_len..], BOOTSTRAP_SCRIPT);
    }

    /// The script is the one place a token is handled on the remote side. It
    /// must pin `CODEG_TOKEN` (so the server never prints its "generated a
    /// token" line) and must bind to loopback only.
    #[test]
    fn script_pins_the_token_and_binds_to_loopback() {
        assert!(BOOTSTRAP_SCRIPT.contains("CODEG_TOKEN=\"$TOKEN\""));
        assert!(BOOTSTRAP_SCRIPT.contains("CODEG_HOST=127.0.0.1"));
        assert!(
            BOOTSTRAP_SCRIPT.contains("umask 077"),
            "state and log files must never be created group/world readable"
        );
    }

    /// The bearer token must never reach a curl argv. `/proc/<pid>/cmdline` is
    /// world-readable on a default Linux, so a `-H "Authorization: Bearer …"`
    /// argument publishes the credential to every other account on the remote
    /// host for the duration of the call. It goes through a 0600 `-K` config
    /// file instead.
    #[test]
    fn health_check_never_puts_the_token_in_an_argv() {
        // No curl invocation may carry an inline Authorization header.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("-H \"Authorization"),
            "the token must not be passed as a curl -H argument"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("Authorization: Bearer ${_token}"),
            "the token must not be interpolated into an argv string"
        );
        // It must instead be written to a config file read with -K.
        assert!(
            BOOTSTRAP_SCRIPT.contains("-K \"$CURL_AUTH_CFG\""),
            "the health check must read its header from a config file"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("chmod 600 \"$CURL_AUTH_CFG\""),
            "the config file holding the token must be owner-only"
        );
        // And that file must be removed on every exit path.
        assert!(
            BOOTSTRAP_SCRIPT.contains("rm -f \"$CURL_AUTH_CFG\""),
            "the token config file must be cleaned up"
        );
    }

    /// A recorded pid is not proof of ownership: pid numbers are recycled, and a
    /// state file that outlives a reboot almost certainly names an unrelated
    /// process. The script must verify identity via `/proc/<pid>/exe` before it
    /// believes anything about a recorded pid.
    #[test]
    fn a_recorded_pid_is_verified_against_our_own_install_path() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("pid_is_our_server"),
            "there must be an ownership predicate"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("readlink \"/proc/${_pid}/exe\""),
            "ownership must be established from the process's actual executable"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("\"${INSTALL_DIR}/codeg-server\"")
                && BOOTSTRAP_SCRIPT.contains("\"${VERSIONS_DIR}/\"*\"/codeg-server\""),
            "both the stable runtime and legacy version directories must be recognized"
        );
    }

    #[test]
    fn runtime_path_is_stable_and_legacy_layout_is_migrated() {
        assert!(BOOTSTRAP_SCRIPT.contains("INSTALL_DIR=\"${ROOT}/runtime\""));
        assert!(BOOTSTRAP_SCRIPT.contains("LEGACY_INSTALL_DIR="));
        assert!(BOOTSTRAP_SCRIPT.contains("mv \"$LEGACY_INSTALL_DIR\" \"$INSTALL_DIR\""));
        assert!(
            !BOOTSTRAP_SCRIPT.contains("INSTALL_DIR=\"${VERSIONS_DIR}/${CODEG_REMOTE_VERSION}\""),
            "the running path must not depend on the desktop version"
        );
    }

    #[test]
    fn bootstrap_accepts_a_remote_version_that_differs_from_the_seed() {
        let outcome = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":42000,\"token\":\"t\",\
             \"version\":\"9.9.9\",\"reused\":true}",
        )
        .unwrap();
        assert_eq!(outcome.version, "9.9.9");
    }

    #[test]
    fn legacy_process_path_remains_accepted_during_migration() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("\"${VERSIONS_DIR}/\"*\"/codeg-server\""),
            "a still-running pre-migration server must remain recognizable"
        );
    }

    /// The script must never signal a process it cannot prove it owns, and must
    /// never kill a *reused* instance merely because a health check failed —
    /// that server may be mid-run on somebody's agent work.
    ///
    /// The only `kill` permitted is of a pid this script forked itself moments
    /// earlier in the start loop.
    #[test]
    fn no_kill_path_acts_on_a_recorded_or_unhealthy_instance() {
        // Enumerate every kill in the script and check what it targets.
        let kills: Vec<&str> = BOOTSTRAP_SCRIPT
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("kill ") && !line.starts_with("kill -0 "))
            .collect();

        for line in &kills {
            assert!(
                line.contains("\"$pid\""),
                "the only killable pid is the one this run forked; found: {line}"
            );
        }
        assert_eq!(
            kills.len(),
            1,
            "exactly one kill site (the failed start attempt) is expected, found: {kills:?}"
        );

        // `kill -0` is a liveness probe, not a signal, and is still allowed —
        // but never as a substitute for the ownership check.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("kill \"$RUNNING_PID\""),
            "a recorded pid must never be signalled"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("kill -9 \"$RUNNING_PID\""),
            "a recorded pid must never be force-killed"
        );
        // An alive-but-unhealthy instance of ours is reported, not terminated.
        assert!(
            BOOTSTRAP_SCRIPT.contains("instance_unhealthy"),
            "an unhealthy owned instance must fail safe with a diagnostic"
        );
    }

    /// `instance_unhealthy` must reach the user as an actionable message rather
    /// than a generic failure, since the resolution is manual.
    #[test]
    fn an_unhealthy_instance_is_reported_without_being_killed() {
        let err = parse_reply(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"error\",\"code\":\"instance_unhealthy\",\
             \"message\":\"left alone in case agents are still working\"}",
        )
        .unwrap_err();
        assert!(matches!(
            err.code,
            crate::app_error::AppErrorCode::TaskExecutionFailed
        ));
        assert!(err.message.contains("left alone"));
    }

    /// The lock must be an flock on a fd, not a mkdir/pidfile scheme. A
    /// mkdir lock has an unavoidable window between "created" and "pid written"
    /// during which a second bootstrap sees an ownerless lock; every recovery
    /// rule for that window either deletes a live lock (two servers, one
    /// database) or wedges the host.
    #[test]
    fn locking_uses_flock_and_never_deletes_a_live_lock() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("flock -w \"$CODEG_REMOTE_LOCK_WAIT\" 9"),
            "the lock must be a bounded flock on a dedicated fd"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("exec 9>>\"$LOCK_FILE\""),
            "the lock fd must be opened for the life of the shell"
        );
        // flock is required, not optional — a fallback would reintroduce the
        // race it exists to remove.
        assert!(
            BOOTSTRAP_SCRIPT.contains("for tool in curl tar flock"),
            "flock must be a hard precondition"
        );
        // No pid-based lock reclamation anywhere.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("mkdir \"$LOCK_DIR\""),
            "the mkdir lock must be gone"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("rm -rf \"$LOCK_DIR\""),
            "no code may delete a lock it cannot prove is dead"
        );
        // The lock *file* must survive cleanup: unlinking it would let the next
        // run lock a fresh inode while this one still holds the old one.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("rm -f \"$LOCK_FILE\""),
            "the lock file must not be unlinked"
        );
    }

    /// A signal must not merely tidy up and fall through to the install/start
    /// path with the lock released.
    #[test]
    fn signal_traps_exit_rather_than_continuing_unlocked() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("trap 'log \"interrupted\"; exit 1' INT TERM HUP"),
            "INT/TERM/HUP must terminate the run, not just clean up"
        );
    }

    /// The detached server must not inherit this script's stdin (it would
    /// consume the unparsed remainder of the script) nor the lock fd (it would
    /// hold the flock for its entire lifetime and deadlock every later
    /// bootstrap, including one that only wants to reuse it).
    #[test]
    fn the_background_server_drops_stdin_and_the_lock_fd() {
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("nohup \"$SERVER_BIN\" </dev/null >>\"$SERVER_LOG\" 2>&1 9>&- &"),
            "the server must be started with stdin from /dev/null and fd 9 closed"
        );
    }

    /// A 2xx alone is not evidence: any local service could answer on a recycled
    /// port. The probe must match codeg-server's own health body, and the
    /// reported version must come from that live response rather than from the
    /// state file (which only records what was once requested).
    #[test]
    fn health_check_validates_the_response_body_and_sources_the_version_from_it() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("*'\"status\":\"ok\"'*"),
            "the health check must require the documented status field"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("HEALTH_VERSION="),
            "the live version must be captured from the health body"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("${HEALTH_VERSION:-${RUNNING_VERSION:-unknown}}"),
            "a reused instance must report the version it is actually serving"
        );
    }

    /// An install that skipped checksum verification would be the most
    /// dangerous possible regression in this feature.
    #[test]
    fn script_verifies_the_download_before_executing_it() {
        assert!(BOOTSTRAP_SCRIPT.contains("checksum_mismatch"));
        assert!(BOOTSTRAP_SCRIPT.contains(".sha256"));
        // The chmod +x must come after the comparison.
        let verify = BOOTSTRAP_SCRIPT
            .find("checksum verified")
            .expect("verify log");
        let chmod = BOOTSTRAP_SCRIPT
            .find("chmod 700 \"${staged}")
            .expect("chmod");
        assert!(
            verify < chmod,
            "binaries must not be made executable before verification"
        );
    }
}
