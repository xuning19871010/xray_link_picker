"""root 公钥登录：精确公钥、Ubuntu drop-in 先匹配生效、本机一次性 sshd 能用测试钥匙登录。"""
from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "ops" / "root_authorized_keys"
DROPIN = ROOT / "ops" / "00-root-pubkey.conf"
USER_LINE = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC28Ehzv/Bzi8MWpk1QkRgaR/rYyhFxHaFywmF0/wNg1isq5dpUgerw35eOeY3DwekOMkSMgRcmRcUkExFnJjz1cjtqBBoV1hctfo9xyAnZAkrEirtSgFoUMGnKZW1I3FQXg8t1HL6c6ZEgZWg5SeuOQEIb3gzImHA7xxCumUXXI8QB225q72pGET1JRjdRO9/2izkATmB3ibTNRqK4xZ/N37qHsJVQLWytmZbznIQTKENLfVDVxubd1wYJzDqet8Pnv3L/dxlLalCxXERuv4wCAuC+f+qVBlAB2BqK30Jhgt9BNl6Ywulbz9zu77bwiELkWUmOrdELGdTWkLwTaUZGNsjxQOceXUnMvhAkQ/QheOk4xFAURpQwyz1Xu2yWn+lGtaSMdpQZjdlqo54gNf6VUqcv0IZ4G1DSdQ4r+bpQ22sFKCVVg1jBJvAC8MSWhD1VLqPVV8jybvkIm40dGZokRCrYpdI8RNMZ7i21De6KTi55djllOmaYqjIl/VhfiFc= "
    "shou_gang@163.com"
)
VERIFIER_LINE = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEQAlCxBuFQLdCiOXrX7ghPQfYnud0tknqql7xx/anz "
    "xray-temporary-verification"
)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestRootPubkeySSH(unittest.TestCase):
    def test_authorized_keys_are_exact(self) -> None:
        lines = KEYS.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines, [USER_LINE, VERIFIER_LINE])
        fingerprints = subprocess.check_output(
            ["ssh-keygen", "-lf", str(KEYS)], text=True
        )
        self.assertIn("SHA256:", fingerprints)
        self.assertEqual(fingerprints.count("\n"), 2)

    def test_dropin_wins_over_ubuntu_cloud_init(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            drop = base / "sshd_config.d"
            drop.mkdir()
            (drop / "50-cloud-init.conf").write_text(
                "PasswordAuthentication no\n", encoding="utf-8"
            )
            (drop / "00-root-pubkey.conf").write_text(
                DROPIN.read_text(encoding="utf-8"), encoding="utf-8"
            )
            subprocess.check_call(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(base / "host"), "-N", ""]
            )
            cfg = base / "sshd_config"
            cfg.write_text(
                "\n".join(
                    [
                        f"Include {drop}/*.conf",
                        f"HostKey {base / 'host'}",
                        "PermitRootLogin no",
                        "PasswordAuthentication yes",
                        "PubkeyAuthentication no",
                        "KbdInteractiveAuthentication yes",
                        "AuthenticationMethods password",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            out = subprocess.check_output(
                ["/usr/sbin/sshd", "-T", "-f", str(cfg)], text=True
            )
            got = {
                line.split()[0]: " ".join(line.split()[1:])
                for line in out.splitlines()
                if line.split()[0]
                in {
                    "permitrootlogin",
                    "passwordauthentication",
                    "kbdinteractiveauthentication",
                    "pubkeyauthentication",
                    "authenticationmethods",
                }
            }
            self.assertIn(got["permitrootlogin"], {"prohibit-password", "without-password"})
            self.assertEqual(got["passwordauthentication"], "no")
            self.assertEqual(got["kbdinteractiveauthentication"], "no")
            self.assertEqual(got["pubkeyauthentication"], "yes")
            self.assertEqual(got["authenticationmethods"], "publickey")

    def test_local_sshd_accepts_only_authorized_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            subprocess.check_call(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(base / "host"), "-N", ""]
            )
            subprocess.check_call(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(base / "client"), "-N", ""]
            )
            subprocess.check_call(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(base / "other"), "-N", ""]
            )
            auth = base / "authorized_keys"
            auth.write_text(
                (base / "client.pub").read_text(encoding="utf-8")
                + USER_LINE
                + "\n"
                + VERIFIER_LINE
                + "\n",
                encoding="utf-8",
            )
            os.chmod(auth, 0o600)
            port = _free_port()
            cfg = base / "sshd_config"
            cfg.write_text(
                "\n".join(
                    [
                        f"Port {port}",
                        "ListenAddress 127.0.0.1",
                        f"HostKey {base / 'host'}",
                        f"PidFile {base / 'sshd.pid'}",
                        f"AuthorizedKeysFile {auth}",
                        "PasswordAuthentication no",
                        "KbdInteractiveAuthentication no",
                        "ChallengeResponseAuthentication no",
                        "PubkeyAuthentication yes",
                        "AuthenticationMethods publickey",
                        "UsePAM no",
                        "StrictModes no",
                        "PrintMotd no",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            proc = subprocess.Popen(
                ["/usr/sbin/sshd", "-f", str(cfg), "-D", "-e"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                try:
                    proc.wait(timeout=0.3)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    err = proc.stderr.read().decode() if proc.stderr else ""
                    self.fail(f"sshd exited early: {err}")
                common = [
                    "ssh",
                    "-p",
                    str(port),
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "BatchMode=yes",
                    f"{os.environ.get('USER', 'runner')}@127.0.0.1",
                    "true",
                ]
                ok = subprocess.run(
                    common[:3] + ["-i", str(base / "client")] + common[3:],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(ok.returncode, 0, ok.stderr)
                denied = subprocess.run(
                    common[:3] + ["-i", str(base / "other")] + common[3:],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(denied.returncode, 0)
                password = subprocess.run(
                    common[:3]
                    + ["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
                    + common[3:],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(password.returncode, 0)
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
