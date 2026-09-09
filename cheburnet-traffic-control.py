#!/usr/bin/env python3
"""ЧебурNET Traffic Control — independent host ingress blocklist manager.

Автор: Леонид Копысов · GitHub: leonidkopysov · Telegram: @kopysovleonid
Copyright (c) 2026 Леонид Копысов. SPDX-License-Identifier: MIT
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
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

VERSION = "0.1.0-alpha.6"
TABLE = "cheburnet_tc"
ROOT = Path("/var/lib/cheburnet-traffic-control")
STATE = ROOT / "state.json"
BIN = Path("/usr/local/bin/cheburnet-traffic-control")
SHORT_BIN = Path("/usr/local/bin/ctc")
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

COMMAND_ALIASES = {
    "s": "status", "t": "top", "c": "check", "r": "rules",
    "l": "logs", "u": "update", "on": "activate", "ok": "confirm",
    "off": "disable", "fix": "repair",
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


def status_mark(ok, good="РАБОТАЕТ", bad="НЕ РАБОТАЕТ"):
    return colored("✓ " + good, "green", "bold") if ok else colored("✗ " + bad, "red", "bold")


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


def run(*args, data=None, check=True, timeout=60):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=check, timeout=timeout)


def os_release(path=OS_RELEASE):
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
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


def rdap_lookup(ip):
    """Resolve one address without touching the shared cache."""
    try:
        opener = urllib.request.build_opener(HTTPSOnly())
        with opener.open("https://rdap.org/ip/" + host(ip), timeout=3) as response:
            raw = response.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            raise ValueError("Ответ RDAP превышает допустимый размер")
        return rdap_label(json.loads(raw))
    except (OSError, ValueError, TypeError, AttributeError):
        return "Не определено (RDAP недоступен)"


def lookup_many(addresses):
    """Resolve cold RDAP entries concurrently and update the cache once."""
    path = ROOT / "rdap-cache.json"
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    now = time.time()
    cache = {k: v for k, v in cache.items()
             if isinstance(v, dict) and now - v.get("time", 0) < 7 * 86400}
    result = {ip: cache[ip]["label"] for ip in addresses
              if ip in cache and isinstance(cache[ip].get("label"), str)}
    missing = [ip for ip in addresses if ip not in result]
    if missing:
        with ThreadPoolExecutor(max_workers=min(10, len(missing))) as pool:
            labels = list(pool.map(rdap_lookup, missing))
        for ip, label in zip(missing, labels):
            result[ip] = label
            if not label.startswith("Не определено"):
                cache[ip] = dict(time=now, label=label)
    if len(cache) >= 1000:
        cache = dict(sorted(cache.items(), key=lambda item: item[1]["time"], reverse=True)[:999])
    atomic(path, json.dumps(cache, ensure_ascii=False))
    return result


def lookup(ip):
    return lookup_many([ip])[ip]


def top(resolve=True):
    journal = run("journalctl", "-k", "--since", "24 hours ago", "--grep=CBTC[46] ",
                  "-n", "10000", "-o", "json", "--no-pager",
                  check=False, timeout=300)
    # journalctl returns 1 when the filter has no matches; this is not a fault.
    if journal.returncode not in (0, 1):
        raise subprocess.CalledProcessError(journal.returncode, journal.args,
                                            journal.stdout, journal.stderr)
    text = journal.stdout
    rows = journal_top(text)
    labels = lookup_many([ip for ip, _ in rows]) if resolve and rows else {}
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
        label = labels[ip] if resolve else "Расшифровка отключена"
        print(f"  {index:<3} {colored(f'{ip:<39}', 'white')} {colored(f'{count:>8}', 'yellow')}  {colored(label, 'magenta')}")
    if not rows:
        print(colored("  ○ За последние 24 часа заблокированных обращений пока нет.", "dim"))
    print(colored("  Владелец сети не обязательно отправитель или хостер.", "dim"))
    rule("─", style="blue")


def journal_output(*args):
    result = run("journalctl", *args, check=False, timeout=300)
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(result.returncode, result.args,
                                            result.stdout, result.stderr)
    return result.stdout.strip()


def print_logs():
    print()
    rule()
    print(colored("  ЖУРНАЛЫ ЧЕБУРNET TRAFFIC CONTROL", "cyan", "bold"))
    print()
    print(colored("  ПОСЛЕДНИЕ БЛОКИРОВКИ", "magenta", "bold"))
    blocked = journal_output("-k", "--since", "24 hours ago", "--grep=CBTC[46] ",
                             "-n", "30", "-o", "short-iso", "--no-pager")
    print(blocked or colored("  ○ За последние 24 часа записей нет.", "dim"))
    print()
    print(colored("  ОБНОВЛЕНИЕ ВНЕШНИХ СПИСКОВ", "magenta", "bold"))
    updates = journal_output("-u", UNIT + "-update.service", "--since", "7 days ago",
                             "-n", "20", "-o", "short-iso", "--no-pager")
    print(updates or colored("  ○ За последние 7 дней записей нет.", "dim"))
    rule()


def fetch_lists():
    # No partial updates: failure of any of the three sources aborts the operation.
    return {name: download(url) for name, url in SOURCES.items()}


def atomic(path, text, mode=0o600):
    fd, temp = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def path_exists(path):
    """Like lexists(): broken symlinks must also count as occupied paths."""
    return os.path.lexists(path)


def shortcut_valid():
    try:
        return SHORT_BIN.is_symlink() and os.readlink(SHORT_BIN) == str(BIN)
    except OSError:
        return False


def write_shortcut():
    if path_exists(SHORT_BIN) and not shortcut_valid():
        raise ValueError(f"Путь {SHORT_BIN} занят чужим файлом; ярлык ctc не перезаписан.")
    temporary = SHORT_BIN.parent / f".{SHORT_BIN.name}.new-{os.getpid()}"
    temporary.unlink(missing_ok=True)
    try:
        os.symlink(str(BIN), temporary)
        os.replace(temporary, SHORT_BIN)
    finally:
        temporary.unlink(missing_ok=True)


def save(state):
    atomic(STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load():
    state = json.loads(STATE.read_text(encoding="utf-8"))
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
    run("nft", "-c", "-f", "-", data=rules, timeout=300)
    run("nft", "-f", "-", data=rules, timeout=300)


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
Description=ЧебурNET Traffic Control: восстановление проверенных списков
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
Description=ЧебурNET Traffic Control: обновление внешних списков
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart={BIN} update
TimeoutStartSec=300
""",
        UNIT + "-update.timer": f"""[Unit]
Description=ЧебурNET Traffic Control: ежедневное обновление списков
[Timer]
OnBootSec=15min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
[Install]
WantedBy=timers.target
""",
        UNIT + "-rollback.service": f"""[Unit]
Description=ЧебурNET Traffic Control: откат неподтверждённого включения
[Service]
Type=oneshot
ExecStart={BIN} rollback
""",
        UNIT + "-rollback.timer": """[Unit]
Description=ЧебурNET Traffic Control: таймер безопасного включения
[Timer]
OnActiveSec=120s
AccuracySec=1s
"""}


def unit_state(action, name):
    try:
        result = run("systemctl", action, name, check=False)
        return result.stdout.strip() or "неизвестно"
    except (OSError, subprocess.SubprocessError):
        return "недоступно"


def format_updated(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).astimezone().strftime("%d.%m.%Y %H:%M:%S %Z")
    except (OSError, OverflowError, TypeError, ValueError):
        return "неизвестно"


def component_report(state):
    """Compact, human-readable report used by status and the main menu."""
    try:
        table = present()
    except (OSError, ValueError, subprocess.SubprocessError):
        table = False
    enabled = (ROOT / "enabled").exists()
    pending = (ROOT / "pending").exists()
    service_enabled = unit_state("is-enabled", UNIT + ".service") == "enabled"
    timer_active = unit_state("is-active", UNIT + "-update.timer") == "active"
    if pending:
        protection = colored("◷ ПРОБНОЕ ВКЛЮЧЕНИЕ", "yellow", "bold")
    elif enabled and table:
        protection = colored("✓ АКТИВНА", "green", "bold")
    elif enabled:
        protection = colored("✗ ТРЕБУЕТ ВОССТАНОВЛЕНИЯ", "red", "bold")
    else:
        protection = colored("○ ВЫКЛЮЧЕНА", "yellow", "bold")
    print()
    rule("─", style="blue")
    print(colored("  ОТЧЁТ О РАБОТЕ КОМПОНЕНТОВ", "blue", "bold"))
    print()
    print(f"  Защита входящего трафика : {protection}")
    if table:
        table_status = status_mark(True, "ЗАГРУЖЕНА")
    elif enabled or pending:
        table_status = status_mark(False, bad="ОТСУТСТВУЕТ")
    else:
        table_status = colored("○ не загружена — защита выключена", "yellow")
    print(f"  Таблица nftables          : {table_status}")
    if enabled:
        startup = status_mark(service_enabled, "ВКЛЮЧЕНО", "ВЫКЛЮЧЕНО")
        updates = status_mark(timer_active, "АКТИВНО", "НЕАКТИВНО")
    else:
        startup = colored("○ включится после подтверждения защиты", "yellow")
        updates = colored("○ включится после подтверждения защиты", "yellow")
    print(f"  Восстановление при старте : {startup}")
    print(f"  Ежедневное обновление     : {updates}")
    print(f"  Внешние списки            : {sum(len(x) for x in state['lists'].values())} сетей/адресов")
    print(f"  Разрешённые IP            : {len(state['allow'])}")
    print(f"  Журналирование блокировок : {'ВКЛЮЧЕНО' if state.get('logging') else 'ВЫКЛЮЧЕНО'}")
    print(f"  Последнее обновление      : {format_updated(state.get('updated'))}")
    rule("─", style="blue")


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


def brand_header():
    print()
    rule()
    print(colored("  ЧебурNET · TRAFFIC CONTROL", "cyan", "bold"))
    print(colored("  УПРАВЛЕНИЕ ЗАЩИТОЙ ВХОДЯЩЕГО ТРАФИКА", "magenta", "bold"))
    print(colored("  Тестовая версия · " + VERSION, "yellow"))
    print(colored("  Автор и разработчик: Леонид Копысов", "white"))
    print(colored("  GitHub: leonidkopysov · Telegram: @kopysovleonid", "dim"))
    rule()


def confirm_install_start(confirmed=False):
    if confirmed:
        return
    if not sys.stdin.isatty():
        raise ValueError("Для автоматической установки добавьте --yes.")
    brand_header()
    print(colored("  ПЕРЕД НАЧАЛОМ", "cyan", "bold"))
    print()
    print("  Скрипт проверит зависимости, загрузит три внешних списка,")
    print("  сохранит конфигурацию и установит службы восстановления.")
    print(colored("  Фильтрация не включится до отдельной пробной активации.", "yellow", "bold"))
    print(colored("  Держите доступ к консоли VPS до завершения проверки.", "red", "bold"))
    print()
    if not ask_yes("  Продолжить установку?"):
        raise ValueError("Установка отменена пользователем.")


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
    # CheburNET Vision writes this non-secret field; never read node.env/.env secrets.
    try:
        if path.is_symlink():
            return ""
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > 65536:
            return ""
        values = json.loads(path.read_text(encoding="utf-8")).get('panel_ips', '')
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
    if path_exists(SHORT_BIN) and not shortcut_valid():
        raise ValueError(f"Путь {SHORT_BIN} уже занят. Установка ничего не изменила.")
    if any((SYSTEMD / name).exists() for name in service_files()):
        raise ValueError("Конфликт имён systemd. Ничего не перезаписано.")
    if shutil.which("traffic-guard") or Path("/opt/trafficguard-manager.sh").exists():
        raise ValueError("Обнаружен TrafficGuard. Сначала удалите его штатно на тестовом сервере.")
    ports, allow = install_inputs(args)
    state = dict(schema=1, ssh_ports=ports, allow=sorted(set(allow)), manual=[],
                 lists=fetch_lists(), updated=int(time.time()), logging=args.logging)
    run("nft", "-c", "-f", "-", data=render(state), timeout=300)
    root_created = not ROOT.exists()
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        save(state)
        atomic(BIN, Path(__file__).read_text(encoding="utf-8"), 0o755)
        write_shortcut()
        for name, body in service_files().items():
            atomic(SYSTEMD / name, body, 0o644)
        run("systemctl", "daemon-reload")
    except BaseException:
        for path in [*(SYSTEMD / name for name in service_files()), SHORT_BIN, BIN, STATE]:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            run("systemctl", "daemon-reload", check=False)
        except (OSError, subprocess.SubprocessError):
            pass
        if root_created:
            try:
                ROOT.rmdir()
            except OSError:
                pass
        raise
    print(colored("  ✓ Компонент установлен, конфигурация сохранена.", "green", "bold"))
    print(colored("  ○ Фильтрация пока выключена. Для проверки выберите пробное включение в меню.", "yellow"))


def activate():
    state = load()
    if (ROOT / "enabled").exists() or (ROOT / "pending").exists():
        raise ValueError("Защита уже включена или ожидает подтверждения. Выполните: ctc s")
    atomic(ROOT / "pending", str(time.time()))
    run("systemctl", "restart", UNIT + "-rollback.timer")
    apply(state)
    print(colored("  ◷ Защита пробно включена на 120 секунд.", "yellow", "bold"))
    print("  Проверьте НОВОЕ SSH-подключение, панель и VPN.")
    print(colored("  Если всё работает, подтвердите: ctc ok", "green", "bold"))
    print(colored("  Без подтверждения правила будут автоматически удалены.", "red"))


def disable(units=True):
    (ROOT / "enabled").unlink(missing_ok=True)
    remove_table()
    (ROOT / "pending").unlink(missing_ok=True)
    if units:
        run("systemctl", "disable", "--now", UNIT + "-update.timer", check=False)
        run("systemctl", "disable", UNIT + ".service", check=False)
    print(colored("  ○ Защита ЧебурNET выключена; остальные правила firewall не изменены.", "yellow"))


def file_is_secure(path, executable=False):
    try:
        mode = path.stat().st_mode
        return path.is_file() and path.stat().st_uid == 0 and not mode & 0o022 and (not executable or mode & 0o111)
    except OSError:
        return False


def lists_complete(state):
    lists = state.get("lists")
    if not isinstance(lists, dict):
        return False
    expected = set(SOURCES)
    actual = set(lists)
    return actual == expected and all(lists.get(name) for name in expected)


def diagnostic_items(state):
    items = []

    def add(name, ok, detail):
        items.append((name, bool(ok), detail))

    missing = missing_packages()
    tools_ok = bool(shutil.which("systemctl")) and bool(shutil.which("journalctl"))
    add("Системные зависимости", not missing and tools_ok and sys.version_info >= (3, 10),
        "установлены" if not missing and tools_ok else "не все команды доступны")
    add("Система инициализации", tools_ok and Path("/run/systemd/system").is_dir(),
        "systemd работает" if Path("/run/systemd/system").is_dir() else "systemd не активен")
    lists_ok = lists_complete(state)
    add("Три внешних списка", lists_ok,
        "загружены" if lists_ok else "состав списков неполный")
    try:
        try:
            rules_exist = present()
        except (OSError, ValueError, subprocess.SubprocessError):
            rules_exist = False
        rendered = render(state, rules_exist)
        syntax = run("nft", "-c", "-f", "-", data=rendered,
                     check=False, timeout=300).returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError):
        syntax = False
    add("Синтаксис правил", syntax, "проверен nftables" if syntax else "проверка не пройдена")
    try:
        binary_current = (file_is_secure(BIN, executable=True) and
                          BIN.read_text(encoding="utf-8") == Path(__file__).read_text(encoding="utf-8"))
    except OSError:
        binary_current = False
    add("Основной файл", binary_current,
        "актуален и защищён" if binary_current else "отсутствует, устарел или имеет неверные права")
    add("Короткая команда ctc", shortcut_valid(), str(SHORT_BIN))
    try:
        config_ok = (ROOT.stat().st_mode & 0o777 == 0o700 and
                     STATE.stat().st_mode & 0o777 == 0o600 and STATE.stat().st_uid == 0)
    except OSError:
        config_ok = False
    add("Права конфигурации", config_ok, "0700/0600" if config_ok else "требуют восстановления")
    units_ok = True
    for name, body in service_files().items():
        path = SYSTEMD / name
        try:
            units_ok = (units_ok and file_is_secure(path) and
                        path.read_text(encoding="utf-8") == body)
        except OSError:
            units_ok = False
    add("Службы systemd", units_ok, "актуальны" if units_ok else "требуют восстановления")
    enabled = (ROOT / "enabled").exists()
    pending = (ROOT / "pending").exists()
    try:
        table = present()
    except (OSError, ValueError, subprocess.SubprocessError):
        table = False
    if pending:
        add("Пробное включение", table and unit_state("is-active", UNIT + "-rollback.timer") == "active",
            "защитный таймер активен")
    elif enabled:
        add("Рабочая таблица", table, "загружена" if table else "отсутствует")
        service_ok = unit_state("is-enabled", UNIT + ".service") == "enabled"
        timer_ok = (unit_state("is-enabled", UNIT + "-update.timer") == "enabled" and
                    unit_state("is-active", UNIT + "-update.timer") == "active")
        add("Автовосстановление", service_ok, "включено" if service_ok else "выключено")
        add("Автообновление", timer_ok, "таймер активен" if timer_ok else "таймер неактивен")
    else:
        add("Выключенный режим", not table, "правила не применены" if not table else "найдена лишняя таблица")
    return items


def print_diagnostics(state):
    items = diagnostic_items(state)
    print()
    rule()
    print(colored("  САМОДИАГНОСТИКА ЧЕБУРNET", "cyan", "bold"))
    print()
    for name, ok, detail in items:
        mark = colored("✓", "green", "bold") if ok else colored("✗", "red", "bold")
        print(f"  {mark} {name}: {detail}")
    failed = sum(not ok for _, ok, _ in items)
    print()
    if failed:
        print(colored(f"  Обнаружено проблем: {failed}. Запустите: ctc fix", "red", "bold"))
    else:
        print(colored("  ✓ Все проверяемые компоненты работают штатно.", "green", "bold"))
    rule()
    return failed


def repair(state, confirmed=False):
    if (ROOT / "pending").exists():
        raise ValueError("Сначала завершите пробное включение командой ctc ok либо ctc off.")
    if not confirmed:
        if not sys.stdin.isatty():
            raise ValueError("Для автоматического восстановления добавьте --yes.")
        if not ask_yes("  Исправить обнаруженные компоненты автоматически?"):
            raise ValueError("Восстановление отменено пользователем.")
    if not lists_complete(state):
        repaired_state = json.loads(json.dumps(state))
        repaired_state["lists"] = fetch_lists()
        repaired_state["updated"] = int(time.time())
        commit(repaired_state, state)
        state = repaired_state
    current_source = Path(__file__).read_text(encoding="utf-8")
    ROOT.chmod(0o700)
    STATE.chmod(0o600)
    atomic(BIN, current_source, 0o755)
    write_shortcut()
    for name, body in service_files().items():
        atomic(SYSTEMD / name, body, 0o644)
    run("systemctl", "daemon-reload")
    if (ROOT / "enabled").exists():
        apply(state)
        run("systemctl", "enable", UNIT + ".service")
        run("systemctl", "enable", "--now", UNIT + "-update.timer")
    else:
        remove_table()
        run("systemctl", "disable", "--now", UNIT + "-update.timer", check=False)
        run("systemctl", "disable", "--now", UNIT + ".service", check=False)
    print(colored("  ✓ Восстановление завершено. Повторяю диагностику.", "green", "bold"))
    return print_diagnostics(state)


def print_status(state):
    component_report(state)
    print()
    print(colored("  НАСТРОЙКИ", "cyan", "bold"))
    print(f"  Версия                    : {VERSION}")
    print(f"  Порты SSH                 : {', '.join(map(str, state['ssh_ports']))}")
    print(f"  Разрешённые IP            : {', '.join(state['allow'])}")
    print(f"  Ручные блокировки         : {len(state['manual'])}")
    for name, entries in state["lists"].items():
        print(f"  Список {name:<18}: {len(entries)} записей")
    print()
    print(colored("  Полные правила: ctc r", "dim"))


def print_rules():
    print()
    rule()
    print(colored("  ПОЛНЫЕ ПРАВИЛА NFTABLES", "cyan", "bold"))
    rule()
    if not present():
        print(colored("  ○ Таблица ЧебурNET сейчас не загружена.", "yellow"))
        return
    print(run("nft", "list", "table", "inet", TABLE, timeout=300).stdout)


def execute(args):
    cmd = args.command
    if cmd == "install":
        install(args)
        return
    state = load()
    if cmd == "top":
        top(not args.no_resolve)
    elif cmd == "status":
        if args.json:
            print(json.dumps({"version": VERSION, "table_present": present(),
                  "enabled": (ROOT / "enabled").exists(), "pending": (ROOT / "pending").exists(),
                  "updated": state["updated"], "sources": {k: len(v) for k, v in state["lists"].items()},
                  "allow": state["allow"], "ssh_ports": state["ssh_ports"], "manual": state["manual"]},
                  ensure_ascii=False, indent=2))
        else:
            print_status(state)
    elif cmd == "rules":
        print_rules()
    elif cmd == "logs":
        print_logs()
    elif cmd == "check":
        return print_diagnostics(state)
    elif cmd == "repair":
        return repair(state, args.yes)
    elif cmd == "activate":
        activate()
    elif cmd == "confirm":
        pending = ROOT / "pending"
        if not pending.exists() or time.time() - float(pending.read_text(encoding="utf-8")) >= 120 or not present():
            raise ValueError("Нет действующего пробного включения; выполните ctc on снова.")
        atomic(ROOT / "enabled", "1\n")
        try:
            run("systemctl", "enable", UNIT + ".service")
            run("systemctl", "enable", "--now", UNIT + "-update.timer")
        except BaseException:
            (ROOT / "enabled").unlink(missing_ok=True)
            raise
        pending.unlink()
        run("systemctl", "stop", UNIT + "-rollback.timer")
        print(colored("  ✓ Защита подтверждена: восстановление и обновление включены.", "green", "bold"))
    elif cmd == "rollback":
        if (ROOT / "pending").exists():
            disable()
    elif cmd == "restore":
        if (ROOT / "pending").exists():
            disable(units=False)
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
        if shortcut_valid():
            SHORT_BIN.unlink(missing_ok=True)
        BIN.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        print("✓ Программа, короткая команда и службы удалены. Конфигурация сохранена в " + str(ROOT))
    elif cmd in ("update", "ban", "unban", "allow", "disallow"):
        if (ROOT / "pending").exists():
            raise ValueError("Сначала подтвердите или выключите пробный режим: ctc ok либо ctc off.")
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
        action = "Три внешних списка обновлены." if cmd == "update" else "Изменения сохранены."
        print(colored("  ✓ " + action, "green", "bold"))
        print("  Исключения и SSH имеют приоритет над блокировками.")
        if cmd == "unban":
            print("Удалён только ручной бан. Для исключения из внешних списков используйте allow IP.")


def menu():
    while True:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        brand_header()
        installed = STATE.exists()
        if installed:
            try:
                state = load()
                component_report(state)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                print(colored("  ✗ Отчёт недоступен: " + safe_label(exc), "red", "bold"))
        else:
            print()
            print(colored("  ○ Компонент ещё не установлен.", "yellow", "bold"))
        print()
        print(colored("  ГЛАВНОЕ МЕНЮ", "magenta", "bold"))
        print()
        if not installed:
            menu_line("1", "Установить компонент (защита останется выключенной)", "green")
        else:
            menu_line("1", "Показать краткое состояние", "blue")
            menu_line("2", "Обновить три внешних списка", "blue")
            menu_line("3", "Добавить ручной бан IP или CIDR", "yellow")
            menu_line("4", "Снять точный ручной бан", "green")
            menu_line("5", "Добавить IP в исключения", "green")
            menu_line("6", "Удалить IP из исключений", "yellow")
            menu_line("7", "Пробно включить защиту на 120 секунд", "yellow")
            menu_line("8", "Подтвердить пробное включение", "green")
            menu_line("9", "Выключить защиту", "yellow")
            menu_line("10", "Удалить компонент", "red")
            menu_line("11", "Самодиагностика и исправление", "magenta")
            menu_line("12", "Показать полные правила nftables", "blue")
            menu_line("13", "Показать последние журналы", "blue")
        menu_line("0", "Выход", "white")
        if installed:
            try:
                top()
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                print()
                print(colored("  ✗ Топ-10 временно недоступен: " + safe_label(exc), "red"))
        print()
        rule("─", style="cyan")
        choice = input(colored("  Выберите действие: ", "cyan", "bold")).strip()
        if choice == "0":
            return
        command = ("install" if not installed and choice == "1" else
                   {"1": "status", "2": "update", "3": "ban", "4": "unban",
                    "5": "allow", "6": "disallow", "7": "activate", "8": "confirm",
                    "9": "disable", "10": "uninstall", "11": "check",
                    "12": "rules", "13": "logs"}.get(choice) if installed else None)
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
            problems = main(args)
            if command == "check" and problems and ask_yes("  Исправить обнаруженные проблемы?"):
                main(["repair", "--yes"])
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            print(colored("  ✗ " + str(exc), "red", "bold"))
        if command == "uninstall":
            return
        if command == "install":
            continue
        input(colored("  Enter — вернуться в меню: ", "dim"))


def normalize_argv(argv):
    values = list(argv)
    if values and values[0] in COMMAND_ALIASES:
        values[0] = COMMAND_ALIASES[values[0]]
    return values


def main(argv=None):
    direct_invocation = argv is None
    argv = normalize_argv(sys.argv[1:] if argv is None else argv)
    if not argv:
        if not sys.stdin.isatty():
            raise ValueError("Без терминала укажите команду, например --help.")
        if os.geteuid() != 0:
            raise ValueError("Запуск только от root.")
        menu()
        return
    parser = argparse.ArgumentParser(
        description="ЧебурNET Traffic Control — управление защитой входящего трафика. Тестовая версия.")
    parser.add_argument("--version", action="version", version=VERSION, help="показать версию")
    subs = parser.add_subparsers(dest="command", required=True, title="команды")
    inst = subs.add_parser("install", help="установить компонент без включения защиты")
    inst.add_argument("--ssh-port", action="append", type=int, help="порт SSH; можно указать несколько раз")
    inst.add_argument("--allow", action="append", default=[], help="разрешённый IP; можно указать несколько раз")
    inst.add_argument("--yes", action="store_true", help="Подтвердить автоматическую установку")
    inst.add_argument("--no-logging", action="store_false", dest="logging", help="отключить журнал блокировок")
    inst.set_defaults(logging=True)
    top_parser = subs.add_parser("top", help="показать топ-10 заблокированных IP")
    top_parser.add_argument("--no-resolve", action="store_true", help="не запрашивать организации через RDAP")
    status_parser = subs.add_parser("status", help="показать краткий отчёт")
    status_parser.add_argument("--json", action="store_true", help="вывести машинный JSON")
    command_help = {
        "rules": "показать полные правила nftables", "logs": "показать последние журналы",
        "check": "выполнить самодиагностику",
        "activate": "пробно включить защиту", "confirm": "подтвердить пробное включение",
        "disable": "выключить защиту", "restore": "восстановить правила из локальной копии",
        "rollback": "выполнить аварийный откат", "update": "обновить три внешних списка",
    }
    for cmd, help_text in command_help.items():
        subs.add_parser(cmd, help=help_text)
    repair_parser = subs.add_parser("repair", help="исправить обнаруженные проблемы")
    repair_parser.add_argument("--yes", action="store_true", help="подтвердить автоматическое восстановление")
    address_help = {
        "ban": "добавить ручную блокировку", "unban": "удалить точную ручную блокировку",
        "allow": "добавить IP в исключения", "disallow": "удалить IP из исключений",
    }
    for cmd, help_text in address_help.items():
        subs.add_parser(cmd, help=help_text).add_argument("address", help="IP или допустимый CIDR")
    uninstall_parser = subs.add_parser("uninstall", help="удалить программу и службы")
    uninstall_parser.add_argument("--yes", action="store_true", help="подтвердить удаление")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError("Запуск только от root.")
    if args.command == "install":
        confirm_install_start(args.yes)
    if args.command == "repair" and not args.yes:
        if not sys.stdin.isatty():
            raise ValueError("Для автоматического восстановления добавьте --yes.")
        brand_header()
        if not ask_yes("  Запустить восстановление компонентов?"):
            raise ValueError("Восстановление отменено пользователем.")
        args.yes = True
    try:
        if args.command != "check":
            ensure_dependencies(auto_install=args.command in ("install", "repair"))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise ValueError(str(exc)) from exc
    os.umask(0o077)
    if args.command == "top":
        # Slow external RDAP queries must never delay the activation rollback lock.
        return execute(args)
    # Root-owned /run lock serializes timer, user changes, activation and rollback.
    with open("/run/cheburnet-traffic-control.lock", "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = execute(args)
    if args.command == "install" and direct_invocation and sys.stdin.isatty():
        menu()
    return result


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n○ Операция прервана пользователем.", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print("\n✗ Ввод завершён до окончания операции.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print("✗ " + str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
