#!/usr/bin/env python3
"""ЧебурNET Traffic Control — independent host ingress blocklist manager.

Автор: Леонид Копысов · GitHub: leonidkopysov · Telegram: @kopysovleonid
Copyright (c) 2026 Леонид Копысов. SPDX-License-Identifier: MIT
"""
import argparse
from collections import Counter
import fcntl
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

VERSION = "0.1.0-alpha.4"
TABLE = "cheburnet_tc"
ROOT = Path("/var/lib/cheburnet-traffic-control")
STATE = ROOT / "state.json"
BIN = Path("/usr/local/bin/cheburnet-traffic-control")
UNIT = "cheburnet-traffic-control"
SYSTEMD = Path("/etc/systemd/system")
BASE = "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/"
SOURCES = {name: BASE + name + ".list" for name in
           ("antiscanner", "government_networks", "skipa")}
MAX_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 150000
CA_CERT = Path("/etc/ssl/certs/ca-certificates.crt")
OS_RELEASE = Path("/etc/os-release")

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m",
}


def colored(text, *styles):
    """Use ANSI only in an interactive terminal; logs and pipes stay clean."""
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        return str(text)
    return "".join(ANSI[x] for x in styles) + str(text) + ANSI["reset"]


def rule(char="━", width=62, style="cyan"):
    print(colored(char * width, style))


def menu_line(key, label, style="white"):
    print("  " + colored(f"[{key:>2}]", "bold", style) + "  " + colored(label, style))


def menu_status():
    if not STATE.exists():
        return colored("НЕ УСТАНОВЛЕН", "yellow", "bold")
    if (ROOT / "pending").exists():
        return colored("ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ", "yellow", "bold")
    if (ROOT / "enabled").exists():
        try:
            return colored("АКТИВЕН", "green", "bold") if present() else colored("ТРЕБУЕТ ВОССТАНОВЛЕНИЯ", "red", "bold")
        except (OSError, subprocess.SubprocessError, ValueError):
            return colored("СТАТУС НЕДОСТУПЕН", "red", "bold")
    return colored("ВЫКЛЮЧЕН", "yellow", "bold")


def run(*args, data=None, check=True):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=check, timeout=60)


def os_release(path=OS_RELEASE):
    values = {}
    try:
        for line in path.read_text().splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"\'')
    except OSError:
        pass
    return values


def missing_packages():
    packages = []
    if not shutil.which("nft"):
        packages.append("nftables")
    if not CA_CERT.is_file() or CA_CERT.stat().st_size == 0:
        packages.append("ca-certificates")
    return packages


def apt_install(packages):
    info = os_release()
    family = " ".join((info.get("ID", ""), info.get("ID_LIKE", ""))).lower().split()
    if not set(family) & {"debian", "ubuntu"} or not shutil.which("apt-get"):
        raise ValueError("Автоустановка пакетов поддерживается только в Ubuntu и Debian с apt-get.")
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    print(colored("  ◷ Обновляю индекс пакетов…", "blue"))
    subprocess.run(["apt-get", "update"], check=True, timeout=600, env=env)
    print(colored("  ◷ Устанавливаю: " + ", ".join(packages), "blue"))
    subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", *packages],
                   check=True, timeout=900, env=env)


def ensure_dependencies(auto_install=False):
    if sys.version_info < (3, 10):
        raise ValueError("Требуется Python 3.10 или новее.")
    packages = missing_packages()
    if packages and not auto_install:
        raise ValueError("Не установлены пакеты: " + ", ".join(packages) + ".")
    if packages:
        print(colored("  Найдены отсутствующие пакеты: " + ", ".join(packages), "yellow"))
        apt_install(packages)
    remaining = missing_packages()
    if remaining:
        raise ValueError("После установки не найдены: " + ", ".join(remaining) + ".")
    if not shutil.which("systemctl") or not shutil.which("journalctl"):
        raise ValueError("Не найдены systemctl/journalctl; требуется systemd.")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("systemd установлен, но не работает как система инициализации.")
    print(colored("  ✓ Зависимости проверены.", "green"))


def networks(text):
    """Strict parser: comments/blank lines allowed; any bad entry aborts update."""
    result = []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        net = ipaddress.ip_network(value, strict=False)
        if net.prefixlen == 0:
            raise ValueError("Список содержит маршрут /0; применение запрещено.")
        result.append(net)
        if len(result) > MAX_ENTRIES:
            raise ValueError("Слишком много записей в списке.")
    if not result:
        raise ValueError("Пустой список не принимается.")
    return [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in result if n.version == version)]


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ValueError("Переход с HTTPS запрещён.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url):
    opener = urllib.request.build_opener(HTTPSOnly())
    with opener.open(url, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Список превышает допустимый размер.")
    return networks(raw.decode("utf-8-sig"))


def journal_top(text):
    counts = Counter()
    for line in text.splitlines():
        try:
            message = json.loads(line).get("MESSAGE", "")
        except (ValueError, AttributeError):
            continue
        if not isinstance(message, str) or not re.search(r"\bCBTC[46] ", message):
            continue
        found = re.search(r"\bSRC=([0-9a-fA-F:.]+)(?:\s|$)", message)
        if found:
            try:
                counts[host(found[1])] += 1
            except ValueError:
                pass
    return counts.most_common(10)


def safe_label(value):
    return "".join(ch for ch in str(value) if ch.isprintable())[:70]


def rdap_label(data):
    network = safe_label(data.get("name") or data.get("handle") or "Сеть не указана")
    names = []
    for entity in data.get("entities", []):
        card = entity.get("vcardArray", [])
        if len(card) == 2 and "registrant" in entity.get("roles", []):
            for field in card[1]:
                if len(field) >= 4 and field[0] in ("org", "fn"):
                    names.append(safe_label(field[3]))
    return " / ".join(dict.fromkeys(names))[:100] or network


def lookup(ip):
    path = ROOT / "rdap-cache.json"
    try:
        cache = json.loads(path.read_text())
    except (OSError, ValueError):
        cache = {}
    entry = cache.get(ip)
    if entry and time.time() - entry["time"] < 7 * 86400:
        return entry["label"]
    try:
        opener = urllib.request.build_opener(HTTPSOnly())
        with opener.open("https://rdap.org/ip/" + host(ip), timeout=3) as response:
            raw = response.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            raise ValueError("RDAP response too large")
        label = rdap_label(json.loads(raw))
    except (OSError, ValueError, TypeError, AttributeError):
        return "Не определено (RDAP недоступен)"
    cache = {k: v for k, v in cache.items() if time.time() - v["time"] < 7 * 86400}
    if len(cache) >= 1000:
        cache.pop(next(iter(cache)))
    cache[ip] = dict(time=time.time(), label=label)
    atomic(path, json.dumps(cache, ensure_ascii=False))
    return label


def top(resolve=True):
    text = run("journalctl", "-k", "--since", "24 hours ago", "--grep=CBTC[46] ",
               "-n", "10000", "-o", "json", "--no-pager").stdout
    rows = journal_top(text)
    print()
    rule("─", style="blue")
    print(colored("  ТОП-10 ЗАБЛОКИРОВАННЫХ IP", "blue", "bold"))
    print(colored("  Период: 24 часа · анализ: до 10 000 записей журнала", "dim"))
    print(colored("  Это записи блокировок, а не число сканирований или атак.", "yellow"))
    if resolve and rows:
        print(colored("  Организация: внешний RDAP · кэш 7 дней", "magenta"))
    print()
    print(colored(f"  {'№':<3} {'IP':<39} {'Пакетов':>8}  Организация / сеть", "cyan", "bold"))
    for index, (ip, count) in enumerate(rows, 1):
        label = lookup(ip) if resolve else "Расшифровка отключена"
        print(f"  {index:<3} {colored(f'{ip:<39}', 'white')} {colored(f'{count:>8}', 'yellow')}  {colored(label, 'magenta')}")
    if not rows:
        print(colored("  Пока нет записей: нужны логирование и новые блокировки.", "dim"))
    print(colored("  Владелец сети не обязательно отправитель или хостер.", "dim"))
    rule("─", style="blue")


def fetch_lists():
    # No partial updates: failure of any of the three sources aborts the operation.
    return {name: download(url) for name, url in SOURCES.items()}


def atomic(path, text, mode=0o600):
    fd, temp = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save(state):
    atomic(STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load():
    state = json.loads(STATE.read_text())
    if state.get("schema") != 1:
        raise ValueError("Неизвестная версия конфигурации.")
    return state


def host(value):
    return str(ipaddress.ip_address(value))


def render(state, exists=False):
    ports = sorted(set(int(p) for p in state["ssh_ports"]))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Некорректные SSH-порты.")
    allowed = [ipaddress.ip_network(host(x)) for x in state["allow"]]
    blocked = []
    for entries in list(state["lists"].values()) + [state["manual"]]:
        blocked.extend(ipaddress.ip_network(x, strict=False) for x in entries)
    if any(n.prefixlen == 0 for n in blocked):
        raise ValueError("Блокировка /0 запрещена.")
    lines = [f"delete table inet {TABLE}"] if exists else []
    lines += [f"table inet {TABLE} {{"]
    for prefix, items in (("allow", allowed), ("block", blocked)):
        for version in (4, 6):
            nets = list(ipaddress.collapse_addresses(n for n in items if n.version == version))
            lines += [f" set {prefix}{version} {{", f"  type ipv{version}_addr;", "  flags interval;"]
            if nets:
                lines += ["  elements = { " + ", ".join(map(str, nets)) + " };"]
            lines += [" }"]
    lines += [" chain ingress {", "  type filter hook input priority -10; policy accept;",
              '  iifname "lo" return', "  ct state established,related return",
              "  tcp dport { " + ", ".join(map(str, ports)) + " } return",
              "  ip saddr @allow4 return", "  ip6 saddr @allow6 return"]
    for version in (4, 6):
        proto = "ip" if version == 4 else "ip6"
        if state.get("logging"):
            lines += [f'  {proto} saddr @block{version} limit rate 5/minute burst 10 packets log prefix "CBTC{version} "']
        lines += [f"  {proto} saddr @block{version} counter drop"]
    return "\n".join(lines + [" }", "}", ""])


def present():
    tables = json.loads(run("nft", "-j", "list", "tables").stdout)
    return any(x.get("table", {}).get("family") == "inet" and
               x.get("table", {}).get("name") == TABLE for x in tables["nftables"])


def apply(state):
    rules = render(state, present())
    run("nft", "-c", "-f", "-", data=rules)
    run("nft", "-f", "-", data=rules)


def remove_table():
    if present():
        run("nft", "delete", "table", "inet", TABLE)


def commit(state, old):
    if (ROOT / "enabled").exists():
        apply(state)
        try:
            save(state)
        except BaseException:
            apply(old)
            raise
    else:
        save(state)


def service_files():
    return {
        UNIT + ".service": f"""[Unit]
Description=CheburNET Traffic Control: restore validated local lists
After=network-pre.target ufw.service nftables.service
Before=network.target
[Service]
Type=oneshot
ExecStart={BIN} restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
""",
        UNIT + "-update.service": f"""[Unit]
Description=CheburNET Traffic Control: refresh lists
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart={BIN} update
TimeoutStartSec=300
""",
        UNIT + "-update.timer": f"""[Unit]
Description=CheburNET Traffic Control: daily list refresh
[Timer]
OnBootSec=15min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
[Install]
WantedBy=timers.target
""",
        UNIT + "-rollback.service": f"""[Unit]
Description=CheburNET Traffic Control: unconfirmed activation rollback
[Service]
Type=oneshot
ExecStart={BIN} rollback
""",
        UNIT + "-rollback.timer": """[Unit]
Description=CheburNET Traffic Control: activation safety timer
[Timer]
OnActiveSec=120s
AccuracySec=1s
"""}


def port_list(value):
    ports = sorted(set(int(x) for x in value.replace(',', ' ').split()))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Порты должны быть числами от 1 до 65535.")
    return ports


def ip_list(value):
    values = sorted(set(host(x) for x in value.replace(',', ' ').split()))
    if not values:
        raise ValueError("Укажите хотя бы один IP.")
    return values


def ask_yes(label):
    while True:
        answer = input(label + " [Д/Н]: ").strip().lower()
        if answer in ("д", "да", "y", "yes"):
            return True
        if answer in ("н", "нет", "n", "no"):
            return False
        print("Введите Д или Н.")


def ask_value(label, candidate, validator):
    if candidate:
        print(label + ": " + candidate)
        if ask_yes("Верно?"):
            return validator(candidate)
    while True:
        try:
            return validator(input(label + " (введите своё значение): ").strip())
        except (ValueError, OSError):
            print("Некорректное значение. Повторите ввод.")


def panel_hint(path=Path('/opt/remnanode/settings.json')):
    # Extract only the validated field; never display or modify the settings file.
    try:
        if path.is_symlink():
            return ""
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > 65536:
            return ""
        values = json.loads(path.read_text()).get('panel_ips', '')
        return " ".join(ip_list(values)) if isinstance(values, str) else ""
    except (OSError, ValueError, AttributeError):
        return ""


def panel_input(value):
    try:
        return ip_list(value)
    except ValueError:
        # Domain only: not a URL, port, CIDR, shell command or list of hostnames.
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', value):
            raise ValueError('Укажите IP или домен без https:// и пути.')
        print('DNS домена может указывать на CDN, а не исходящий IP панели!')
        addresses = sorted(set(host(item[4][0]) for item in socket.getaddrinfo(
            value, None, type=socket.SOCK_STREAM)))
        print('Найдены адреса: ' + ', '.join(addresses))
        if not addresses or not ask_yes('Это именно исходящие IP панели?'):
            raise ValueError('Введите исходящий IP панели вручную.')
        return addresses


def install_inputs(args):
    # Explicit flags remain suitable for unattended installs; never append rejected hints.
    if args.ssh_port or args.allow:
        if not args.ssh_port or not args.allow:
            raise ValueError('Укажите оба параметра --ssh-port и --allow либо запустите install без них.')
        return port_list(' '.join(map(str, args.ssh_port))), ip_list(' '.join(args.allow))
    if not sys.stdin.isatty():
        raise ValueError('Для подтверждений нужен терминал. Либо задайте --ssh-port и --allow.')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    admin, port = '', ''
    if len(connection) == 4:
        try:
            admin = host(connection[0])
            port = str(port_list(connection[3])[0])
        except ValueError:
            admin, port = '', ''
    print('IP SSH-клиента может принадлежать VPN, NAT или промежуточному серверу.')
    admins = ask_value('IP администратора', admin, ip_list)
    ports = ask_value('Порт SSH', port, port_list)
    panel = ask_value('Исходящие IP панели (или её домен для поиска)', panel_hint(), panel_input)
    allowed = sorted(set(admins + panel))
    print('Итог: SSH ' + ', '.join(map(str, ports)) + '; исключения IP: ' + ', '.join(allowed))
    if not ask_yes('Установить с этими настройками?'):
        raise ValueError('Установка отменена. Настройки не записаны.')
    return ports, allowed


def install(args):
    if STATE.exists() or BIN.exists() or present():
        raise ValueError("Установка или таблица уже существует. Автоперезапись запрещена.")
    if any((SYSTEMD / name).exists() for name in service_files()):
        raise ValueError("Конфликт имён systemd. Ничего не перезаписано.")
    if shutil.which("traffic-guard") or Path("/opt/trafficguard-manager.sh").exists():
        raise ValueError("Обнаружен TrafficGuard. Сначала удалите его штатно на тестовом сервере.")
    ports, allow = install_inputs(args)
    state = dict(schema=1, ssh_ports=ports, allow=sorted(set(allow)), manual=[],
                 lists=fetch_lists(), updated=int(time.time()), logging=args.logging)
    run("nft", "-c", "-f", "-", data=render(state))
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(state)
    atomic(BIN, Path(__file__).read_text(), 0o755)
    for name, body in service_files().items():
        atomic(SYSTEMD / name, body, 0o644)
    run("systemctl", "daemon-reload")
    print("✓ Установлено. Фильтрация ещё выключена. Выполните: cheburnet-traffic-control activate")


def activate():
    state = load()
    if (ROOT / "enabled").exists() or (ROOT / "pending").exists():
        raise ValueError("Уже включено или ожидает confirm. См. status.")
    atomic(ROOT / "pending", str(time.time()))
    run("systemctl", "restart", UNIT + "-rollback.timer")
    apply(state)
    print("◷ Включено на 120 секунд. Проверьте НОВОЕ SSH-подключение и связь с панелью.")
    print("Затем: cheburnet-traffic-control confirm. Без подтверждения фильтрация отключится.")


def disable():
    (ROOT / "enabled").unlink(missing_ok=True)
    remove_table()
    (ROOT / "pending").unlink(missing_ok=True)
    run("systemctl", "disable", "--now", UNIT + "-update.timer", check=False)
    run("systemctl", "disable", UNIT + ".service", check=False)
    print("○ Собственная фильтрация выключена; остальные правила не изменены.")


def execute(args):
    cmd = args.command
    if cmd == "install":
        install(args)
        return
    state = load()
    if cmd == "top":
        top(not args.no_resolve)
    elif cmd == "status":
        print(json.dumps({"version": VERSION, "table_present": present(),
              "enabled": (ROOT / "enabled").exists(), "pending": (ROOT / "pending").exists(),
              "updated": state["updated"], "sources": {k: len(v) for k, v in state["lists"].items()},
              "allow": state["allow"], "ssh_ports": state["ssh_ports"], "manual": state["manual"]},
              ensure_ascii=False, indent=2))
        if present():
            print(run("nft", "list", "table", "inet", TABLE).stdout)
    elif cmd == "activate":
        activate()
    elif cmd == "confirm":
        pending = ROOT / "pending"
        if not pending.exists() or time.time() - float(pending.read_text()) >= 120 or not present():
            raise ValueError("Нет действующего пробного включения; выполните activate снова.")
        atomic(ROOT / "enabled", "1\n")
        try:
            run("systemctl", "enable", UNIT + ".service")
            run("systemctl", "enable", "--now", UNIT + "-update.timer")
        except BaseException:
            (ROOT / "enabled").unlink(missing_ok=True)
            raise
        pending.unlink()
        run("systemctl", "stop", UNIT + "-rollback.timer")
        print("✓ Подтверждено: автозагрузка и обновление включены.")
    elif cmd == "rollback":
        if (ROOT / "pending").exists():
            disable()
    elif cmd == "restore":
        if (ROOT / "pending").exists():
            disable()
        elif (ROOT / "enabled").exists():
            apply(state)
    elif cmd == "disable":
        disable()
    elif cmd == "uninstall":
        if not args.yes:
            raise ValueError("Удаление требует --yes. Списки сохранятся в " + str(ROOT))
        disable()
        run("systemctl", "stop", UNIT + "-rollback.timer", UNIT + ".service")
        for name in service_files():
            (SYSTEMD / name).unlink(missing_ok=True)
        BIN.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        print("✓ Программа и её systemd-файлы удалены. Конфигурация сохранена в " + str(ROOT))
    elif cmd in ("update", "ban", "unban", "allow", "disallow"):
        if (ROOT / "pending").exists():
            raise ValueError("Сначала confirm либо disable.")
        old = json.loads(json.dumps(state))
        if cmd == "update":
            state["lists"] = fetch_lists()
            state["updated"] = int(time.time())
        else:
            key = "allow" if cmd in ("allow", "disallow") else "manual"
            if key == "allow":
                value = host(args.address)
            else:
                value = str(ipaddress.ip_network(args.address, strict=False))
                if ipaddress.ip_network(value).prefixlen == 0:
                    raise ValueError("Блокировка /0 запрещена.")
            if cmd in ("ban", "allow"):
                state[key] = sorted(set(state[key] + [value]))
            else:
                if value not in state[key]:
                    raise ValueError("Записи нет в локальном списке.")
                state[key].remove(value)
                if key == "allow" and not state[key]:
                    raise ValueError("Нельзя удалить последнее исключение.")
        commit(state, old)
        print("✓ Сохранено. Исключения и SSH имеют приоритет над блокировками.")
        if cmd == "unban":
            print("Удалён только ручной бан. Для исключения из внешних списков используйте allow IP.")


def menu():
    while True:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        print()
        rule()
        print(colored("  ЧебурNET · TRAFFIC CONTROL", "cyan", "bold"))
        print(colored("  ТЕСТОВАЯ ВЕРСИЯ · " + VERSION, "magenta", "bold"))
        print(colored("  Автор и разработчик: Леонид Копысов", "white"))
        print(colored("  Telegram: @kopysovleonid", "dim"))
        print("  Состояние: " + menu_status())
        rule()
        if STATE.exists():
            try:
                main(["top"])
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                print(colored("  Топ недоступен: " + safe_label(exc), "red"))
        print()
        print(colored("  ГЛАВНОЕ МЕНЮ", "cyan", "bold"))
        print()
        menu_line("1", "Показать состояние и правила", "blue")
        menu_line("2", "Обновить три внешних списка", "blue")
        menu_line("3", "Добавить ручной бан IP или CIDR", "yellow")
        menu_line("4", "Снять точный ручной бан", "green")
        menu_line("5", "Добавить IP в исключения", "green")
        menu_line("6", "Удалить IP из исключений", "yellow")
        menu_line("7", "Пробно включить защиту на 120 секунд", "yellow")
        menu_line("8", "Подтвердить пробное включение", "green")
        menu_line("9", "Выключить защиту", "yellow")
        menu_line("10", "Удалить компонент", "red")
        menu_line("0", "Выход", "white")
        print()
        rule("─", style="cyan")
        choice = input(colored("  Выберите действие: ", "cyan", "bold")).strip()
        if choice == "0":
            return
        command = {"1": "status", "2": "update", "3": "ban", "4": "unban",
                   "5": "allow", "6": "disallow", "7": "activate", "8": "confirm",
                   "9": "disable", "10": "uninstall"}.get(choice)
        if not command:
            continue
        args = [command]
        if command in ("ban", "unban", "allow", "disallow"):
            args.append(input(colored("  IP (для ручного бана также CIDR): ", "cyan")).strip())
        if command == "uninstall":
            if input(colored("  Удалить компонент? Введите Д: ", "red", "bold")).strip().lower() != "д":
                continue
            args.append("--yes")
        try:
            main(args)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            print(colored("  ✗ " + str(exc), "red", "bold"))
        if command == "uninstall":
            return
        input(colored("  Enter — вернуться в меню: ", "dim"))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        if not sys.stdin.isatty():
            raise ValueError("Без терминала укажите команду, например --help.")
        menu()
        return
    parser = argparse.ArgumentParser(description="ЧебурNET Traffic Control — фильтрация входящих IP. Тестовая версия.")
    parser.add_argument("--version", action="version", version=VERSION)
    subs = parser.add_subparsers(dest="command", required=True)
    inst = subs.add_parser("install", help="Установка БЕЗ включения фильтрации")
    inst.add_argument("--ssh-port", action="append", type=int)
    inst.add_argument("--allow", action="append", default=[])
    inst.add_argument("--logging", action="store_true", default=True)
    inst.add_argument("--no-logging", action="store_false", dest="logging")
    subs.add_parser("top").add_argument("--no-resolve", action="store_true")
    for cmd in ("status", "activate", "confirm", "disable", "restore", "rollback", "update"):
        subs.add_parser(cmd)
    for cmd in ("ban", "unban", "allow", "disallow"):
        subs.add_parser(cmd).add_argument("address")
    subs.add_parser("uninstall").add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("Запуск только от root.")
    try:
        ensure_dependencies(auto_install=args.command == "install")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    os.umask(0o077)
    if args.command == "top":
        # Slow external RDAP queries must never delay the activation rollback lock.
        execute(args)
        return
    # Root-owned /run lock serializes timer, user changes, activation and rollback.
    with open("/run/cheburnet-traffic-control.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        execute(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print("✗ " + str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
