#!/usr/bin/env python3
"""Automated QEMU boot smoke test for Serenity Linux (ext4 + Rust PID 1 + Nushell + Coreutils + Net).

Emulates minimal ANSI DSR (\x1b[6n -> \x1b[1;1R) so Nushell's reedline
interactive prompt renders and accepts commands over serial ttyS0.
"""
import fcntl
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time


def main() -> int:
    kernel = sys.argv[1]
    disk_img = sys.argv[2]
    qemu_mem = os.environ.get("QEMU_MEM", "512M")

    cmd = ["qemu-system-x86_64"]
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        cmd += ["-enable-kvm", "-cpu", "host"]
    cmd += [
        "-kernel", kernel,
        "-drive", f"file={disk_img},format=raw,if=virtio",
        "-m", qemu_mem,
        "-nographic",
        "-no-reboot",
        "-netdev", "user,id=net0",
        "-device", "virtio-net-pci,netdev=net0",
        "-append", "root=/dev/vda rw rootfstype=ext4 init=/init console=ttyS0 quiet loglevel=3",
    ]

    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True)
    os.close(slave_fd)

    output = bytearray()
    tail = b""
    commands = [
        b"^uname -s -n -m\r",
        b"spkg update\r",
        b"spkg install ripgrep\r",
        b"rg --version\r",
        b"spkg list\r",
        b"spkg remove ripgrep\r",
        b"poweroff\r",
    ]
    cmd_idx = 0
    prompt_ready = False
    last_send = 0.0
    deadline = time.monotonic() + 35.0

    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            r, _, _ = select.select([master_fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

                combined = tail + chunk
                if b"\x1b[6n" in combined:
                    os.write(master_fd, b"\x1b[1;1R")
                    tail = b""
                else:
                    tail = combined[-8:]

                if b"root@serenity" in output:
                    prompt_ready = True

            # Give spkg install ripgrep extra time to download over HTTPS + verify SHA256
            wait_gap = 6.0 if cmd_idx == 3 else 1.2
            if prompt_ready and cmd_idx < len(commands) and (time.monotonic() - last_send) > wait_gap:
                os.write(master_fd, commands[cmd_idx])
                cmd_idx += 1
                last_send = time.monotonic()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        os.close(master_fd)

    raw_text = output.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\].*?(?:\x07|\x1b\\)", "", raw_text)
    checks = [
        ("Serenity PID 1 banner (ext4 root)", "Serenity Linux 0.1.0" in text),
        ("Network interface configured", "10.0.2.15/24 via 10.0.2.2" in text),
        ("uutils/coreutils (uname)", "Linux serenity x86_64" in text),
        ("spkg update", "Updated index" in text),
        ("spkg install ripgrep (GitHub HTTPS + SHA256)", "Installed ripgrep 15.2.0" in text),
        ("ripgrep executes cleanly", "ripgrep 15.2.0" in text),
        ("spkg remove ripgrep", "Removed ripgrep 15.2.0" in text),
        ("Clean poweroff", "executing poweroff" in text),
    ]
    print("\n\n=== Phase 3 Smoke Test Summary ===")
    all_ok = True
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
