//! Secret redaction for anything an SSH workspace puts in front of the user.
//!
//! The remote `codeg-server` prints its access token to stderr when it mints
//! one, and a bootstrap failure is most useful when it carries the remote
//! diagnostics. Those two facts collide: the natural implementation of "show me
//! why it failed" is also the implementation of "copy the bearer token into the
//! desktop log file".
//!
//! The bootstrap avoids the collision at the source — it pins `CODEG_TOKEN` so
//! the server never has a token to announce, and it keeps the server's own
//! stderr in a remote file it never echoes. This module is the second line:
//! every remote-originated string is passed through it before being logged or
//! shown, so a future change on either side cannot quietly start leaking.

/// Replacement written in place of a redacted value.
const MASK: &str = "[redacted]";

/// Longest detail string worth attaching to an error. ssh and the bootstrap can
/// both produce a lot of output; the user needs the reason, not the transcript.
const MAX_DETAIL_LEN: usize = 2000;

/// Patterns whose *remainder of the line* is a secret once the marker is seen.
/// Matched case-insensitively against the line.
///
/// `[server] token:` is the load-bearing one. `codeg-server` prints it
/// unconditionally on startup — not only when it generates one — so pinning
/// `CODEG_TOKEN` in the bootstrap does *not* remove the line, it only changes
/// which value it prints. Anything that ever forwards the remote server log has
/// to mask it here.
const LINE_MARKERS: &[&str] = &[
    "generated an access token (persisted):",
    "[server] token:",
    "codeg_token=",
    "access token:",
    "token:",
    "bearer ",
];

/// Redact secrets from a multi-line diagnostic blob.
///
/// Conservative by construction: it would rather mask a harmless value than
/// pass a token through. The token itself is high-entropy and unquoted in the
/// server's own message, so the marker-based rule is what actually catches it;
/// the JSON rule catches our own protocol line if it ever reaches a log.
pub fn redact_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for (idx, line) in input.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&redact_line(line));
    }
    // `lines()` drops a trailing newline; keep the blob's shape stable for
    // callers that concatenate.
    if input.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn redact_line(line: &str) -> String {
    // Our own protocol line carries the token in JSON. Mask the whole payload:
    // the structured result is consumed programmatically, never from a log.
    if let Some(head) = line.find("CODEG_BOOTSTRAP_RESULT") {
        let (prefix, _) = line.split_at(head);
        return format!("{prefix}CODEG_BOOTSTRAP_RESULT {MASK}");
    }

    let lower = line.to_ascii_lowercase();
    for marker in LINE_MARKERS {
        if let Some(pos) = lower.find(marker) {
            let cut = pos + marker.len();
            // Keep the marker so the message still says what was suppressed.
            let (head, _) = line.split_at(cut);
            return format!("{head}{MASK}");
        }
    }

    // `"token":"…"` in any JSON that reaches a log.
    if let Some(masked) = redact_json_token(line) {
        return masked;
    }

    line.to_string()
}

/// Mask the value of a `"token"` key in a JSON-ish line. Hand-rolled rather
/// than parsed: the input may be a fragment, and a fragment that fails to parse
/// must still be redacted.
///
/// The truncated case is the one that matters. A JSON line cut off mid-value —
/// which is exactly what a bounded read of a stalled stream produces — has an
/// opening quote and no closing one. A parser-based approach returns "not JSON"
/// and passes the fragment through with the secret in it, so an unterminated
/// value is masked to end-of-line rather than skipped.
fn redact_json_token(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let key = lower.find("\"token\"")?;
    let after_key = &line[key + "\"token\"".len()..];
    let colon = after_key.find(':')?;
    let rest = &after_key[colon + 1..];
    let open = rest.find('"')?;
    let value_start = key + "\"token\"".len() + colon + 1 + open + 1;
    match line[value_start..].find('"') {
        Some(offset) => {
            let close = offset + value_start;
            Some(format!("{}{MASK}{}", &line[..value_start], &line[close..]))
        }
        // Unterminated: the rest of the line is the secret, so drop all of it.
        None => Some(format!("{}{MASK}", &line[..value_start])),
    }
}

/// Clamp a diagnostic to something that fits in an error message.
///
/// Truncation happens on a char boundary (`AppCommandError.detail` is a
/// `String`, and slicing mid-codepoint would panic), and the result says it was
/// truncated so nobody reads a cut-off message as the whole story.
pub fn truncate_for_detail(input: &str) -> String {
    if input.len() <= MAX_DETAIL_LEN {
        return input.to_string();
    }
    let mut end = MAX_DETAIL_LEN;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &input[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact line `codeg-server` writes when it mints a token. This is the
    /// leak this module exists to stop.
    #[test]
    fn redacts_the_servers_generated_token_notice() {
        let line = "[SERVER] No CODEG_TOKEN set; generated an access token (persisted): \
                    9f8a7b6c5d4e3f2a1b";
        let out = redact_secrets(line);
        assert!(!out.contains("9f8a7b6c5d4e3f2a1b"), "token survived: {out}");
        assert!(out.contains("generated an access token (persisted):"));
        assert!(out.contains(MASK));
    }

    #[test]
    fn redacts_env_assignments_and_bearer_headers() {
        for (input, secret) in [
            ("CODEG_TOKEN=supersecret", "supersecret"),
            ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
            ("access token: hunter2", "hunter2"),
        ] {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input} leaked {secret}: {out}");
        }
    }

    #[test]
    fn redacts_our_own_protocol_line() {
        let out = redact_secrets(
            "CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"port\":42000,\"token\":\"leaky\"}",
        );
        assert!(!out.contains("leaky"), "{out}");
        assert!(out.starts_with("CODEG_BOOTSTRAP_RESULT "));
    }

    #[test]
    fn redacts_a_json_token_field_in_isolation() {
        let out = redact_secrets("responded with {\"token\": \"abc123\", \"port\": 1}");
        assert!(!out.contains("abc123"), "{out}");
        assert!(
            out.contains("\"port\": 1"),
            "rest of the line survives: {out}"
        );
    }

    /// Redaction is per-line: an unrelated diagnostic next to a secret must
    /// still reach the user, or the feature becomes undebuggable.
    #[test]
    fn keeps_non_secret_lines_intact() {
        let input = "curl: (6) Could not resolve host: github.com\n\
                     CODEG_TOKEN=secret\n\
                     tar: short read";
        let out = redact_secrets(input);
        assert!(out.contains("Could not resolve host: github.com"));
        assert!(out.contains("tar: short read"));
        assert!(!out.contains("secret"), "{out}");
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn is_case_insensitive_about_markers() {
        let out = redact_secrets("AUTHORIZATION: BEARER Abc123");
        assert!(!out.contains("Abc123"), "{out}");
    }

    #[test]
    fn leaves_ordinary_text_untouched() {
        let input = "Installing codeg-server 0.31.2 for linux-x64";
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn preserves_a_trailing_newline() {
        assert_eq!(redact_secrets("plain\n"), "plain\n");
        assert_eq!(redact_secrets("plain"), "plain");
    }

    /// `codeg-server` prints this on EVERY start, not only when it generates a
    /// token — so pinning `CODEG_TOKEN` in the bootstrap changes the value on
    /// this line, it does not remove the line. Anything forwarding the remote
    /// server log must mask it.
    #[test]
    fn redacts_the_unconditional_server_token_line() {
        let out = redact_secrets("[SERVER] Token: 0f1e2d3c4b5a69788796a5b4c3d2e1f0");
        assert!(
            !out.contains("0f1e2d3c4b5a69788796a5b4c3d2e1f0"),
            "the unconditional startup token line leaked: {out}"
        );
        assert!(out.contains(MASK));
    }

    /// A bounded read of a stalled stream cuts the JSON mid-value: an opening
    /// quote, then the secret, then nothing. A parse-based redactor would call
    /// that "not JSON" and pass the secret through, so it is masked to
    /// end-of-line instead.
    #[test]
    fn redacts_a_truncated_json_token_fragment() {
        for fragment in [
            "{\"status\":\"ok\",\"port\":42000,\"token\":\"abcdef0123456789",
            "…\"token\": \"half-a-secret",
        ] {
            let out = redact_secrets(fragment);
            assert!(
                !out.contains("abcdef0123456789") && !out.contains("half-a-secret"),
                "truncated token survived: {out}"
            );
            assert!(out.ends_with(MASK), "masked to end of line: {out}");
        }
    }

    /// Redaction must survive a payload that is itself cut short, since that is
    /// the shape a timeout produces.
    #[test]
    fn redacts_a_truncated_protocol_line() {
        let out = redact_secrets("CODEG_BOOTSTRAP_RESULT {\"status\":\"ok\",\"token\":\"sec");
        assert!(!out.contains("sec"), "{out}");
    }

    #[test]
    fn truncate_for_detail_is_bounded_and_says_so() {
        let long = "x".repeat(MAX_DETAIL_LEN * 2);
        let out = truncate_for_detail(&long);
        assert!(out.len() < long.len());
        assert!(out.ends_with("… (truncated)"));

        let short = "just this";
        assert_eq!(truncate_for_detail(short), short);
    }

    /// Truncation must not split a UTF-8 codepoint — slicing mid-character
    /// panics, and remote diagnostics are frequently non-ASCII.
    #[test]
    fn truncate_for_detail_respects_char_boundaries() {
        let multibyte = "é".repeat(MAX_DETAIL_LEN);
        let out = truncate_for_detail(&multibyte);
        assert!(out.ends_with("… (truncated)"));
        assert!(out.is_char_boundary(out.len()));
    }
}
