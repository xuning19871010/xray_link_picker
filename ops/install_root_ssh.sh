#!/bin/sh
# 安装 root 公钥登录。00- 片段排在 Ubuntu 50-cloud-init 之前，避免后写的设置被忽略。
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sudo install -d -m 700 /root/.ssh
sudo install -m 600 "$root/ops/root_authorized_keys" /root/.ssh/authorized_keys
sudo install -m 644 "$root/ops/00-root-pubkey.conf" /etc/ssh/sshd_config.d/00-root-pubkey.conf
sudo rm -f /etc/ssh/sshd_config.d/debug.conf
sudo mkdir -p /run/sshd
sudo sshd -t
if pgrep -x sshd >/dev/null 2>&1; then
  sudo kill -HUP "$(pgrep -xo sshd)"
else
  sudo /usr/sbin/sshd
fi
