#!/usr/bin/env bash
# GitHub-hosted Linux runner ONLY. No user SSH credentials or external host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo "Requires a disposable GitHub Actions runner" >&2; exit 1; }
root="$(mktemp -d /tmp/codeg-ssh-ci.XXXXXX)"
test_user=codeg-ssh-ci
home="${root}/home"
# sshd must be able to enter the account's home after dropping privileges.
chmod 755 "$root"
if id "$test_user" >/dev/null 2>&1; then
  echo "Refusing to reuse an existing account" >&2
  exit 1
fi
sudo useradd --create-home --home-dir "$home" --shell /bin/sh --password no-password-login "$test_user"
cleanup() {
  # This named account was created above and belongs exclusively to this test.
  sudo pkill -TERM -u "$test_user" || true
  if [[ -f "$root/sshd.pid" ]]; then
    pid="$(cat "$root/sshd.pid")"
    if ps -p "$pid" -o args= | grep -Fq "$root/sshd_config"; then
      sudo kill "$pid" || true
    fi
  fi
}
trap cleanup EXIT
# Disposable fixture only. Production passwords never use environment variables.
test_password="$(openssl rand -hex 24)"
printf '%s:%s\n' "$test_user" "$test_password" | sudo chpasswd
ssh-keygen -q -t ed25519 -N '' -f "$root/client"
ssh-keygen -q -t ed25519 -N '' -f "$root/host"
sudo install -d -m 700 -o "$test_user" -g "$test_user" "$home/.ssh"
sudo install -m 600 -o "$test_user" -g "$test_user" "$root/client.pub" "$home/.ssh/authorized_keys"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
cat > "$root/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $root/host
PidFile $root/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
AllowUsers $test_user
AllowTcpForwarding yes
X11Forwarding no
PrintMotd no
LogLevel ERROR
EOF
sudo install -d -m 755 /run/sshd
sudo /usr/sbin/sshd -t -f "$root/sshd_config"
sudo /usr/sbin/sshd -f "$root/sshd_config" -E "$root/sshd.log"
# Pin the actual generated host key, never auto-accept an observed key.
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$root/host.pub")" > "$root/known_hosts"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
cat >> "$HOME/.ssh/config" <<EOF

Host codeg-ssh-ci
  HostName 127.0.0.1
  User $test_user
  Port $port
  IdentityFile $root/client
  IdentitiesOnly yes
  UserKnownHostsFile $root/known_hosts
  StrictHostKeyChecking yes
  ControlMaster auto
  ControlPersist 60
  ControlPath $root/control-%r-%h-%p
EOF
ssh-keygen -q -t ed25519 -N '' -f "$root/unrelated-host"
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$root/unrelated-host.pub")" > "$root/changed_known_hosts"
cat >> "$HOME/.ssh/config" <<EOF

Host codeg-ssh-password-ci codeg-ssh-changed-ci
  HostName 127.0.0.1
  User $test_user
  Port $port
  IdentityFile none
  IdentityAgent none
  PubkeyAuthentication no
  PasswordAuthentication yes
Host codeg-ssh-password-ci
  UserKnownHostsFile $root/password_known_hosts
Host codeg-ssh-changed-ci
  UserKnownHostsFile $root/changed_known_hosts
EOF
chmod 600 "$HOME/.ssh/config"
export CODEG_SSH_TEST_PASSWORD="$test_password"
export CODEG_SSH_TEST_FINGERPRINT="$(ssh-keygen -lf "$root/host.pub" -E sha256 | awk '{print $2}')"
export CODEG_SSH_TEST_HOST=codeg-ssh-ci
cd src-tauri
cargo test --features test-utils --lib isolated_sshd_install_reuse_tunnel_and_reconnect -- --ignored --nocapture

cargo build --no-default-features --bin codeg-mcp
export CODEG_SSH_TEST_HELPER="$PWD/target/debug/codeg-mcp"
cargo test --features test-utils --lib isolated_sshd_password_host_trust_and_helper -- --ignored --nocapture
