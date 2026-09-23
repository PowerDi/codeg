//! Minimal OpenSSH askpass child. No logging, Tauri startup, files or secret
//! environment variables: answers travel over an authenticated loopback pipe.
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const ADDRESS_ENV: &str = "CODEG_SSH_ASKPASS_ADDRESS";
pub const TOKEN_ENV: &str = "CODEG_SSH_ASKPASS_TOKEN";
pub const FRAME_LIMIT: usize = 16 * 1024;
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Serialize, Deserialize)]
pub struct AskpassRequest {
    pub token: String,
    pub prompt: String,
}

#[derive(Serialize, Deserialize)]
pub struct AskpassReply {
    pub answer: Option<String>,
}

pub fn valid_answer(answer: &str) -> bool {
    answer.len() <= 4096 && !answer.contains(['\r', '\n', '\0'])
}

/// An endpoint is only useful to a child of this application. Never follow a
/// hostname or accept a non-loopback address supplied through the environment.
fn loopback_address(value: &str) -> io::Result<SocketAddr> {
    let address = value.parse::<SocketAddr>().map_err(io::Error::other)?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(io::Error::other("invalid askpass endpoint"));
    }
    Ok(address)
}

fn exchange(address: SocketAddr, request: &AskpassRequest) -> io::Result<Zeroizing<String>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(ANSWER_TIMEOUT + Duration::from_secs(5)))?;
    let mut frame = serde_json::to_vec(request)?;
    if frame.len() >= FRAME_LIMIT {
        return Err(io::Error::other("askpass request too large"));
    }
    frame.push(b'\n');
    stream.write_all(&frame)?;
    let mut response = Zeroizing::new(Vec::new());
    io::BufReader::new(stream.take((FRAME_LIMIT + 1) as u64)).read_until(b'\n', &mut response)?;
    if response.len() > FRAME_LIMIT || response.last() != Some(&b'\n') {
        return Err(io::Error::other("invalid askpass response"));
    }
    let reply: AskpassReply = serde_json::from_slice(&response)?;
    let answer = Zeroizing::new(
        reply
            .answer
            .ok_or_else(|| io::Error::other("askpass declined"))?,
    );
    if !valid_answer(&answer) {
        return Err(io::Error::other("invalid askpass answer"));
    }
    Ok(answer)
}

pub fn run_if_requested() -> Option<u8> {
    let address = std::env::var_os(ADDRESS_ENV)?;
    // No diagnostics here: stdout belongs exclusively to OpenSSH and errors
    // must never serialize an answer or accidentally start the desktop.
    let result = (|| -> io::Result<()> {
        let address = loopback_address(&address.to_string_lossy())?;
        let token = std::env::var(TOKEN_ENV).map_err(io::Error::other)?;
        if token.len() != 64 {
            return Err(io::Error::other("invalid askpass capability"));
        }
        let prompt = std::env::args()
            .nth(1)
            .ok_or_else(|| io::Error::other("missing SSH prompt"))?;
        let answer = exchange(address, &AskpassRequest { token, prompt })?;
        let mut output = io::stdout().lock();
        output.write_all(answer.as_bytes())?;
        output.write_all(b"\n")?;
        output.flush()
    })();
    Some(if result.is_ok() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bounded_single_line_answers() {
        assert!(valid_answer("password with spaces and \"quotes\""));
        assert!(!valid_answer("first\nsecond"));
        assert!(!valid_answer("secret\r"));
        assert!(!valid_answer("secret\0"));
        assert!(!valid_answer(&"x".repeat(4097)));
    }

    #[test]
    fn helper_cannot_send_credentials_off_machine() {
        assert!(loopback_address("127.0.0.1:1234").is_ok());
        assert!(loopback_address("[::1]:1234").is_ok());
        for invalid in [
            "example.com:22",
            "192.0.2.1:1234",
            "127.0.0.1:0",
            "0.0.0.0:1234",
        ] {
            assert!(loopback_address(invalid).is_err());
        }
    }

    #[test]
    fn helper_exchanges_only_the_answer_and_does_not_trim_passwords() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = String::new();
            io::BufReader::new(socket.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: AskpassRequest = serde_json::from_str(&request).unwrap();
            assert_eq!(request.token, "capability");
            socket
                .write_all(b"{\"answer\":\"  secret with spaces  \"}\n")
                .unwrap();
        });
        let answer = exchange(
            address,
            &AskpassRequest {
                token: "capability".into(),
                prompt: "user@host's password: ".into(),
            },
        )
        .unwrap();
        assert_eq!(answer.as_str(), "  secret with spaces  ");
        server.join().unwrap();
    }
}
