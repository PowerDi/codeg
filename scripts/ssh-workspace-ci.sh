#!/usr/bin/env bash
# GitHub-hosted Linux runner ONLY. No user SSH credentials or external host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo "Requires a disposable GitHub Actions runner" >&2; exit 1; }
root="$(mktemp -d "${RUNNER_TEMP}/codeg-ssh-ci.XXXXXX")"
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
PasswordAuthentication no
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
chmod 600 "$HOME/.ssh/config"
export CODEG_SSH_TEST_HOST=codeg-ssh-ci
cd src-tauri
cargo test --features test-utils --lib isolated_sshd_install_reuse_tunnel_and_reconnect -- --ignored --nocapture
