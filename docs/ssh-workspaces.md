# SSH-managed remote workspaces

The desktop can install and start a prebuilt `codeg-server` on a Linux host,
then connect through an app-owned SSH tunnel. No remote Rust installation,
systemd configuration, exposed HTTP port, or pasted server token is needed.
Existing HTTP connections remain supported.

```text
Desktop UI -> Rust HTTP/WebSocket proxy -> local 127.0.0.1:port
                                              |
                                           OpenSSH
                                              |
                         remote 127.0.0.1:port -> codeg-server
```

Files, Git, terminals and agents run on the remote host using the existing API.
This is not an SFTP mount or local execution against remote files.

## Prerequisites

- Desktop Codeg and the system `ssh` executable on PATH. On Windows, enable
  **OpenSSH Client** in Optional Features.
- A Linux x86_64 or aarch64 host compatible with the upstream glibc binary.
  Alpine/musl, macOS and Windows remote hosts are outside this phase.
- Working key or ssh-agent authentication. Load encrypted keys into the agent
  first. Password and MFA prompts cannot be answered by the application.
- A writable remote home directory, standard Linux utilities, `curl`, `tar`,
  `flock`, and `sha256sum` (or `shasum`). The remote host needs HTTPS access to
  GitHub release assets.
- Verify the host fingerprint through a trusted source, then connect once in a
  terminal to add the correct key to `known_hosts`. Unknown or changed keys
  are rejected. Codeg never automatically accepts them.

An SSH config alias is usually the simplest setup:

```sshconfig
Host build-box
  HostName example.internal
  User developer
  Port 2222
  IdentityFile ~/.ssh/id_ed25519
```

Verify noninteractive access first:

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes build-box true
```

HostName, ProxyJump/ProxyCommand and identity selection follow system OpenSSH
configuration. Only use trusted config files. Codeg disables agent/X11
forwarding, local command execution, backgrounding and multiplexing for its own
processes; its forwards are not delegated to a user-owned ControlMaster.

## Add a connection

1. Open **Manage remote workspace**, then **New connection**.
2. Enter a name and select **SSH (automatic setup)**.
3. Enter the SSH hostname, IP, or config alias, such as `build-box`.
4. Leave username, port and identity file blank to inherit the SSH config.
   A blank port does not override an alias with port 22. The identity field is
   a local file path, not the private key contents.
5. Optionally **Test connection**, then **Save** and open the connection.

Both Test and Save can install/start the remote server. The first operation can
take several minutes, and the form stays disabled while it runs. SSH profiles
have no manually entered bearer token or custom HTTP headers. Switching to HTTP
requires that server's actual URL and token, never a remembered tunnel address.

## Installation, security and lifetime

- The bundled bootstrap downloads the desktop's matching version from the
  upstream `xintaofei/codeg` GitHub release and verifies its published SHA-256
  checksum before installing/executing it. Both `codeg-server` and `codeg-mcp`
  are required. This trusts the upstream HTTPS release and checksum; it is not
  an independent signature verification.
- Files live under `~/.codeg-ssh-workspace/`: `versions/<version>/`, `data/`,
  `run/` and `logs/server.log`. This does not adopt a manually installed
  server's `~/.codeg` database. The token and logs are private to the account;
  do not paste them into an issue. Back up `data/` before removing it.
- Startup is serialized by flock. A healthy existing server is reused. A stale
  PID is checked against its executable path, never blindly signalled. A living
  but unhealthy server is left alone to avoid disrupting active work.
- The server listens on remote loopback; the managed tunnel listens on local
  loopback. Requests to the tunnel bypass HTTP proxy settings. SSH encrypts
  traffic between the machines. No additional public server port is needed.
- An authenticated health response supplies readiness and version. The client
  does not scrape human-readable server logs for ports or tokens. SSH output
  and operation time are bounded, and diagnostic token patterns are redacted.
- Only the locator is saved locally. Runtime tokens and ports remain in Rust
  memory. HTTP calls, transfers and each WebSocket reconnection resolve the
  current endpoint rather than using a persisted local port.
- Closing the last window for a profile, deleting it, or exiting the desktop
  closes local tunnels and cancels in-flight setup. The remote server, agents,
  terminals, files and database are not stopped or deleted.
- Reopening reuses the remote server or starts it if needed. A host reboot
  requires reconnecting; this is not a boot-time service. Host policies that
  terminate user processes can still stop the helper.
- An already-running different server version is not upgraded automatically.
  The connection is refused, leaving work intact. After remote jobs finish,
  stop the verified owned server yourself and reconnect for the matching version.

## Recovery and limitations

- Missing client: install OpenSSH Client and ensure it is visible on PATH.
- Authentication/host key: fix noninteractive access in a terminal. Do not turn
  off fingerprint verification to work around a mismatch.
- Download/checksum failure: check remote HTTPS access and whether upstream
  published the desktop's exact version/architecture. There is no remote build
  or unverified download fallback. Offline and custom-source installs are not
  offered by this UI.
- Alive but unhealthy server: inspect its private log and active work. Verify
  both PID and executable before stopping it. Never remove the data directory
  just to retry a connection.
- Network interruption: WebSocket retries with bounded backoff and rebuilds
  the tunnel. Failed HTTP mutations are not automatically replayed: check the
  outcome before retrying a prompt, write or command. File transfers do not
  automatically resume after interruption.
- Profiles on the same remote account share the installation and data. Use
  separate accounts when separate remote data environments are needed.
- This phase forwards the Codeg API/WebSocket port only. Arbitrary development
  servers, multi-port browser previews, interactive SSH authentication, and
  SSH profile management in web/server mode are not supported.

## Verification

**SSH Workspace Checks** runs frontend lint, tests and static export, Linux
 desktop tests and clippy, server tests, and server/companion clippy. The existing
**Windows Test Build** produces an unsigned Windows x64 installer without
publishing a release.

The isolated-sshd check creates a disposable CI account and pins its generated
host key. With the actual upstream release and production manager it exercises
cold install, concurrent reuse, authenticated HTTP, WebSocket readiness after
rebuild, background lifetime, last-window cleanup and reopening. It uses no
user private key, real server or remote data. Its harness is
`scripts/ssh-workspace-ci.sh` and refuses non-GitHub-runner execution.

These automated checks do not replace testing the built Windows desktop with
your SSH configuration, agent and network. Browser previews and every agent
provider are not covered end to end.
