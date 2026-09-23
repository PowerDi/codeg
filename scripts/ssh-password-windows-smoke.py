"""Test native OpenSSH and the built GUI-subsystem askpass helper on loopback.
No real SSH host, account, keys, password, app database or GUI is used.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import paramiko


def main():
    executable = Path(sys.argv[1]).resolve(strict=True)
    password, capability = secrets.token_hex(32), secrets.token_hex(32)
    key = paramiko.RSAKey.generate(2048)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    prompts, failures = [], []

    class AskpassHandler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            request = json.loads(self.rfile.readline(16 * 1024))
            if not hmac.compare_digest(request.get("token", ""), capability):
                return
            prompt, answer = request["prompt"], None
            if "Are you sure you want to continue connecting" in prompt and fingerprint in prompt:
                prompts.append("hostKey")
                answer = "yes"
            elif prompt.strip().endswith("'s password:"):
                prompts.append("password")
                answer = password
            self.wfile.write((json.dumps({"answer": answer}) + "\n").encode())

    class Broker(socketserver.ThreadingTCPServer):
        daemon_threads = True

    class Server(paramiko.ServerInterface):
        def __init__(self):
            self.ready = threading.Event()

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, supplied):
            valid = username == "codeg-smoke" and hmac.compare_digest(supplied, password)
            return paramiko.AUTH_SUCCESSFUL if valid else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            if command != b"codeg-password-smoke":
                return False
            self.ready.set()
            return True

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(45)
    port = listener.getsockname()[1]

    def serve_ssh():
        try:
            connection, _ = listener.accept()
            with paramiko.Transport(connection) as transport:
                transport.add_server_key(key)
                server = Server()
                transport.start_server(server=server)
                channel = transport.accept(30)
                if channel is None or not server.ready.wait(15):
                    raise RuntimeError("SSH fixture was not authenticated")
                channel.sendall(b"CODEG_WINDOWS_PASSWORD_OK\n")
                channel.send_exit_status(0)
                channel.close()
        except Exception as error:
            failures.append(type(error).__name__)

    ssh_thread = threading.Thread(target=serve_ssh, daemon=True)
    ssh_thread.start()
    with Broker(("127.0.0.1", 0), AskpassHandler) as broker:
        threading.Thread(target=broker.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix="codeg askpass smoke ") as temp:
                helper, known_hosts = Path(temp) / "codeg.exe", Path(temp) / "known_hosts"
                shutil.copy2(executable, helper)
                env = os.environ.copy()
                env.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force", DISPLAY="codeg:0",
                           CODEG_SSH_ASKPASS_ADDRESS="127.0.0.1:%s" % broker.server_address[1],
                           CODEG_SSH_ASKPASS_TOKEN=capability, LC_ALL="C", LANG="C")
                ssh = Path(os.environ["WINDIR"]) / "System32/OpenSSH/ssh.exe"
                command = [str(ssh), "-F", "NUL", "-T", "-o", "BatchMode=no",
                           "-o", "StrictHostKeyChecking=ask", "-o", "FingerprintHash=sha256",
                           "-o", "PasswordAuthentication=yes", "-o", "PubkeyAuthentication=no",
                           "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
                           "-o", 'UserKnownHostsFile="%s"' % known_hosts,
                           "-o", "GlobalKnownHostsFile=NUL", "-o", "ConnectTimeout=10",
                           "-p", str(port), "-l", "codeg-smoke", "127.0.0.1", "codeg-password-smoke"]
                result = subprocess.run(command, input=b"stdin-is-not-the-password\n", capture_output=True,
                                        env=env, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode != 0 or result.stdout.strip() != b"CODEG_WINDOWS_PASSWORD_OK":
                    raise RuntimeError("Native Windows askpass failed: " + result.stderr.decode(errors="replace"))
                if prompts != ["hostKey", "password"] or not known_hosts.is_file():
                    raise RuntimeError("Unexpected host-trust / password prompt flow")
        finally:
            broker.shutdown()
            listener.close()
    ssh_thread.join(timeout=3)
    if failures:
        raise RuntimeError("SSH fixture failed: " + ", ".join(failures))
    print("PASS: Windows OpenSSH, host trust, password IPC, GUI helper and path with spaces")


if __name__ == "__main__":
    main()
