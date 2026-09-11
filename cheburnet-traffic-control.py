#!/usr/bin/env python3
"""ЧебурNET Traffic Control — independent host ingress blocklist manager.

Автор: Леонид Копысов · GitHub: leonidkopysov · Telegram: @kopysovleonid
Copyright (c) 2026 Леонид Копысов. SPDX-License-Identifier: MIT
"""
import argparse
import codecs
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
import fcntl
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request

VERSION = "1.0.1-audit"
WIDTH = 78
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
LABEL_LIMIT = 100
CA_CERT = Path("/etc/ssl/certs/ca-certificates.crt")
OS_RELEASE = Path("/etc/os-release")
LOCK_FILE = Path("/run/cheburnet-traffic-control.lock")
SUPPORTED_SYSTEMS = {"ubuntu": {"22.04", "24.04"}, "debian": {"12"}}
SUPPORTED_ARCHITECTURES = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
}

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m",
    "badge_green": "\033[42m\033[30m", "badge_yellow": "\033[43m\033[30m",
    "badge_red": "\033[41m\033[97m",
}

COMMAND_ALIASES = {
    "s": "status", "t": "top", "c": "check", "r": "rules",
    "l": "logs", "u": "update", "on": "activate",
    "off": "disable", "fix": "repair",
}


def stream_supports_decoration(stream=None):
    stream = stream or sys.stdout
    return (hasattr(stream, "isatty") and stream.isatty()
            and "NO_COLOR" not in os.environ and utf8_output(stream))


def colored(text, *styles, stream=None):
    """Use ANSI only in an interactive terminal; logs and pipes stay clean."""
    stream = stream or sys.stdout
    if not hasattr(stream, "isatty") or not stream.isatty() or "NO_COLOR" in os.environ:
        return str(text)
    return "".join(ANSI[x] for x in styles) + str(text) + ANSI["reset"]


def utf8_output(stream=None):
    """Return whether terminal symbols are safe for the current stdout."""
    encoding = getattr(stream or sys.stdout, "encoding", None)
    if not encoding:
        return False
    try:
        return codecs.lookup(encoding).name == "utf-8"
    except LookupError:
        return False


def symbol(name, stream=None):
    unicode_symbols = {
        "heavy": "─", "light": "─", "ok": "✓", "warn": "!",
        "error": "✗", "info": "›", "idle": "!", "pending": "!",
    }
    ascii_symbols = {
        "heavy": "-", "light": "-", "ok": "[OK]", "warn": "!",
        "error": "[ERR]", "info": ">", "idle": "!", "pending": "!",
    }
    return (unicode_symbols if decorated(stream) else ascii_symbols)[name]


def decorated(stream=None):
    return stream_supports_decoration(stream)


def vislen(text):
    return len(re.sub(r'\x1b\[[0-9;]*m', '', str(text)))


def pad_left(text, width):
    return " " * max(0, width - vislen(text)) + str(text)


def pad_right(text, width):
    return str(text) + " " * max(0, width - vislen(text))


def clip(text, width):
    text = re.sub(r'\x1b\[[0-9;]*m', '', str(text))
    if vislen(text) <= width:
        return text
    ending = "…" if decorated() else "~"
    return text[:max(0, width - 1)] + ending if width else ""


def term_width():
    return max(1, min(shutil.get_terminal_size((80, 24)).columns, WIDTH))


def terminal_width():
    """Fit the interface to the current terminal without exceeding 78 columns."""
    return term_width()


def rule(char=None, width=None, style="cyan"):
    if char in (None, "━", "="):
        char = symbol("heavy")
    elif char in ("─", "-"):
        char = symbol("light")
    print(colored(char * (terminal_width() if width is None else width), style))


def message(kind, text, *styles, file=None):
    marks = {"ok": "ok", "warn": "warn", "error": "error", "info": "info", "pending": "pending"}
    colors = {"ok": "green", "warn": "yellow", "error": "red", "info": "dim", "pending": "yellow"}
    stream = file or sys.stdout
    prefix = f"  {symbol(marks[kind], stream)} "
    available = max(1, terminal_width() - len(prefix))
    lines = textwrap.wrap(str(text), width=available, replace_whitespace=False,
                          drop_whitespace=True) or [""]
    for index, line in enumerate(lines):
        rendered = (prefix if index == 0 else "  ") + line
        print(colored(rendered, colors[kind], *styles, stream=stream), file=file)


def ok(text):
    message("ok", text, "bold")


def warn(text):
    message("warn", text, "bold")


def err(text, file=None):
    message("error", text, "bold", file=file)


def info(text):
    message("info", text)


def pending(text):
    message("pending", text, "bold")


def print_fit(text, *styles, indent=2):
    available = max(1, terminal_width() - indent)
    lines = textwrap.wrap(str(text), width=available, replace_whitespace=False,
                          drop_whitespace=True) or [""]
    for line in lines:
        print(" " * indent + colored(line, *styles))


def field(label, value):
    prefix = "  " + pad_right(label, 25) + " : "
    if vislen(prefix + str(value)) <= terminal_width():
        print(prefix + str(value))
    else:
        print_fit(label + ":", "dim")
        print_fit(re.sub(r'\x1b\[[0-9;]*m', '', str(value)))


def menu_line(key, label, style="white"):
    style = "red" if key == "10" else style
    token = f"[{pad_left(key, 2)}] "
    prefix = "  " + token
    available = max(1, terminal_width() - len(prefix))
    lines = textwrap.wrap(label, width=available) or [""]
    print("  " + colored(token, "bold", style) + colored(lines[0], style))
    for line in lines[1:]:
        print("  " + colored(line, style))


def menu_section(label):
    print()
    print_fit(label, "dim")


def badge(label, style):
    return colored(" " + pad_right(label, vislen("ТРЕБУЕТ ВОССТАНОВЛЕНИЯ")) + " ", "badge_" + style)


def status_mark(ok, good="РАБОТАЕТ", bad="НЕ РАБОТАЕТ"):
    return (colored(symbol("ok") + " " + good, "green", "bold") if ok else
            colored(symbol("error") + " " + bad, "red", "bold"))


def menu_status():
    if not STATE.exists():
        return badge("НЕ УСТАНОВЛЕН", "yellow")
    if (ROOT / "pending").exists():
        return badge("ВКЛЮЧЕНИЕ НЕ ЗАВЕРШЕНО", "yellow")
    if (ROOT / "enabled").exists():
        try:
            return badge("АКТИВЕН", "green") if present() else badge("ТРЕБУЕТ ВОССТАНОВЛЕНИЯ", "red")
        except (OSError, subprocess.SubprocessError, ValueError):
            return badge("СТАТУС НЕДОСТУПЕН", "red")
    return badge("ВЫКЛЮЧЕН", "yellow")


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


def platform_details():
    """Validate the operating system and architecture promised by this release."""
    values = os_release()
    system = values.get("ID", "").lower()
    version = values.get("VERSION_ID", "").strip()
    supported_versions = SUPPORTED_SYSTEMS.get(system)
    if not supported_versions or not any(
            version == item or version.startswith(item + ".") for item in supported_versions):
        expected = "Ubuntu 22.04/24.04 или Debian 12"
        raise ValueError(f"Неподдерживаемая система: {system or 'не определена'} "
                         f"{version or ''}. Требуется {expected}.")
    machine = os.uname().machine.lower()
    architecture = SUPPORTED_ARCHITECTURES.get(machine)
    if not architecture:
        raise ValueError("Неподдерживаемая архитектура: " + machine
                         + ". Поддерживаются amd64 и arm64.")
    return system, version, architecture


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
    pending("Обновляю индекс пакетов…")
    subprocess.run(["apt-get", "update"], check=True, timeout=600, env=env)
    pending("Устанавливаю: " + ", ".join(packages))
    subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", *packages],
                   check=True, timeout=900, env=env)


def ensure_dependencies(auto_install=False):
    if sys.version_info < (3, 10):
        raise ValueError("Требуется Python 3.10 или новее.")
    platform_details()
    packages = missing_packages()
    if packages and not auto_install:
        raise ValueError("Не установлены пакеты: " + ", ".join(packages) + ".")
    if packages:
        warn("Найдены отсутствующие пакеты: " + ", ".join(packages))
        apt_install(packages)
    remaining = missing_packages()
    if remaining:
        raise ValueError("После установки не найдены: " + ", ".join(remaining) + ".")
    if not shutil.which("systemctl") or not shutil.which("journalctl"):
        raise ValueError("Не найдены systemctl/journalctl; требуется systemd.")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("systemd установлен, но не работает как система инициализации.")
    ok("Зависимости проверены.")


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
    collapsed = [n for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in result if n.version == version)]
    if any(net.prefixlen == 0 for net in collapsed):
        raise ValueError("Список после объединения покрывает весь IPv4 или IPv6; применение запрещено.")
    return [str(net) for net in collapsed]


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
    return "".join(ch for ch in str(value) if ch.isprintable())[:LABEL_LIMIT]


def rdap_label(data):
    network = safe_label(data.get("name") or data.get("handle") or "Сеть не указана")
    names = []
    for entity in data.get("entities", []):
        card = entity.get("vcardArray", [])
        if len(card) == 2 and "registrant" in entity.get("roles", []):
            for field in card[1]:
                if len(field) >= 4 and field[0] in ("org", "fn"):
                    names.append(safe_label(field[3]))
    return safe_label(" / ".join(dict.fromkeys(names))) or network


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
    if not isinstance(cache, dict):
        cache = {}
    now = time.time()
    valid_cache = {}
    for key, value in cache.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        timestamp = value.get("time")
        label = value.get("label")
        if (isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool)
                and isinstance(label, str) and 0 <= now - timestamp < 7 * 86400):
            try:
                valid_cache[host(key)] = {"time": float(timestamp), "label": safe_label(label)}
            except ValueError:
                continue
    cache = valid_cache
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


def top(resolve=True, limit=10):
    journal = run("journalctl", "-k", "--since", "24 hours ago", "--grep=CBTC[46] ",
                  "-n", "10000", "-o", "json", "--no-pager",
                  check=False, timeout=300)
    # journalctl returns 1 when the filter has no matches; this is not a fault.
    if journal.returncode not in (0, 1):
        raise subprocess.CalledProcessError(journal.returncode, journal.args,
                                            journal.stdout, journal.stderr)
    text = journal.stdout
    rows = journal_top(text)[:limit]
    labels = lookup_many([ip for ip, _ in rows]) if resolve and rows else {}
    width = terminal_width()
    ip_w = min(21, max([len(ip) for ip, _ in rows] + [15]))
    # On very narrow consoles, preserve the table within the available width.
    ip_w = min(ip_w, max(15, width - 25))
    org_w = max(8, width - 19 - ip_w)
    if 17 + ip_w + org_w > width:
        org_w = max(1, width - 17 - ip_w)
    print()
    rule("─", width, "blue")
    print_fit(f"ТОП-{limit} ЗАБЛОКИРОВАННЫХ IP", "cyan", "bold")
    print_fit("Период: 24 часа · анализ: до 10 000 записей журнала", "dim")
    print_fit("Это записи блокировок, а не число сканирований или атак.", "yellow")
    if resolve and rows:
        print_fit("Организация: внешний RDAP · кэш 7 дней", "magenta")
    print()
    if not rows:
        empty = "Блокировок за 24 часа пока нет"
        if vislen(empty) <= width - 2:
            print("  " + colored(empty.center(width - 2), "dim"))
        else:
            print_fit(empty, "dim")
        return
    if width < 33:
        print_fit("№  IP / пакеты", "cyan", "bold")
        for index, (ip, count) in enumerate(rows, 1):
            print_fit(f"{index}. {ip} / {count}", "white")
            print_fit((labels[ip] if resolve else "-"), "dim")
    else:
        org_w = width - 17 - ip_w
        heading = "  " + pad_left("№", 2) + "  " + pad_right("IP", ip_w) + " " + pad_left("Пакетов", 8) + "  " + clip("Организация", org_w)
        print(colored(heading, "dim"))
        rule("─", width, "dim")
        for index, (ip, count) in enumerate(rows, 1):
            label = clip(safe_label(labels[ip]) if resolve else "-", org_w)
            count_text = f"{count:,}".replace(",", "\u00a0" if decorated() else " ")
            print("  " + pad_left(index, 2) + "  " + pad_right(clip(ip, ip_w), ip_w) + " "
                  + pad_left(count_text, 8) + "  " + label)
    print_fit("Владелец сети не обязательно отправитель или хостер", "dim")


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
    if blocked:
        print(blocked)
    else:
        info("За последние 24 часа записей нет.")
    print()
    print(colored("  ОБНОВЛЕНИЕ ВНЕШНИХ СПИСКОВ", "magenta", "bold"))
    updates = journal_output("-u", UNIT + "-update.service", "--since", "7 days ago",
                             "-n", "20", "-o", "short-iso", "--no-pager")
    if updates:
        print(updates)
    else:
        info("За последние 7 дней записей нет.")
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
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextmanager
def exclusive_lock(path=LOCK_FILE):
    """Open the process lock without following a pre-created symbolic link."""
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        details = os.fstat(fd)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != 0
                or details.st_mode & 0o022):
            raise ValueError(f"Небезопасный файл блокировки: {path}")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as lock:
            fd = -1
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
    finally:
        if fd >= 0:
            os.close(fd)


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
    state = validate_state(state)
    atomic(STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load():
    if path_exists(ROOT) and not directory_is_secure(ROOT):
        raise ValueError("Каталог конфигурации имеет небезопасный тип, владельца или права доступа.")
    if path_exists(STATE) and not file_is_secure(STATE):
        raise ValueError("Файл конфигурации имеет небезопасный тип, владельца или права доступа.")
    try:
        state = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("Компонент не установлен: файл конфигурации отсутствует.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Файл конфигурации повреждён: некорректный JSON.") from exc
    return validate_state(state)


def host(value):
    return str(ipaddress.ip_address(value))


def network_values(values, label, allow_empty=True):
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError(f"Некорректное поле конфигурации «{label}».")
    if not values:
        if allow_empty:
            return []
        raise ValueError(f"Поле конфигурации «{label}» не должно быть пустым.")
    try:
        return networks("\n".join(values))
    except ValueError as exc:
        raise ValueError(f"Некорректное поле конфигурации «{label}»: {exc}") from exc


def reject_default_coverage(values, label):
    try:
        parsed = [ipaddress.ip_network(value, strict=False) for value in values]
    except ValueError as exc:
        raise ValueError(f"Некорректное поле конфигурации «{label}».") from exc
    collapsed = [net for version in (4, 6) for net in ipaddress.collapse_addresses(
        net for net in parsed if net.version == version)]
    if any(net.prefixlen == 0 for net in collapsed):
        raise ValueError(f"Поле «{label}» после объединения покрывает весь IPv4 или IPv6.")


def validate_state(state):
    """Return a canonical, bounded state or reject it before generating firewall rules."""
    if not isinstance(state, dict) or state.get("schema") != 1:
        raise ValueError("Неизвестная или повреждённая версия конфигурации.")
    ports = state.get("ssh_ports")
    if (not isinstance(ports, list) or not ports
            or any(not isinstance(port, int) or isinstance(port, bool)
                   or port < 1 or port > 65535 for port in ports)):
        raise ValueError("Некорректное поле конфигурации «ssh_ports».")
    allow = state.get("allow")
    if not isinstance(allow, list) or not allow or any(not isinstance(value, str) for value in allow):
        raise ValueError("Некорректное поле конфигурации «allow».")
    try:
        allow = sorted(set(host(value) for value in allow))
    except ValueError as exc:
        raise ValueError("Некорректное поле конфигурации «allow».") from exc
    lists = state.get("lists")
    if not isinstance(lists, dict) or set(lists) != set(SOURCES):
        raise ValueError("Некорректный состав внешних списков в конфигурации.")
    normalized_lists = {
        name: network_values(lists[name], f"lists.{name}", allow_empty=False)
        for name in SOURCES
    }
    manual = network_values(state.get("manual"), "manual")
    # A default route may emerge only after lists and manual entries are combined.
    reject_default_coverage(
        [item for values in normalized_lists.values() for item in values] + manual,
        "совокупные блокировки")
    updated = state.get("updated")
    if not isinstance(updated, (int, float)) or isinstance(updated, bool) or updated < 0:
        raise ValueError("Некорректное поле конфигурации «updated».")
    logging = state.get("logging")
    if not isinstance(logging, bool):
        raise ValueError("Некорректное поле конфигурации «logging».")
    return {
        "schema": 1,
        "ssh_ports": sorted(set(ports)),
        "allow": allow,
        "manual": manual,
        "lists": normalized_lists,
        "updated": int(updated),
        "logging": logging,
    }


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
    collapsed_blocked = [n for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in blocked if n.version == version)]
    if any(net.prefixlen == 0 for net in collapsed_blocked):
        raise ValueError("Совокупность блокировок покрывает весь IPv4 или IPv6; применение запрещено.")
    lines = [f"delete table inet {TABLE}"] if exists else []
    lines += [f"table inet {TABLE} {{"]
    for prefix, items in (("allow", allowed), ("block", collapsed_blocked)):
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
TimeoutStartSec=5min
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
TimeoutStartSec=15min
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
Description=ЧебурNET Traffic Control: откат незавершённого включения
[Service]
Type=oneshot
ExecStart={BIN} rollback
TimeoutStartSec=5min
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
        return datetime.fromtimestamp(timestamp).astimezone().strftime("%d.%m.%Y %H:%M")
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
        filtering = colored(symbol("pending") + " ВКЛЮЧЕНИЕ НЕ ЗАВЕРШЕНО", "yellow", "bold")
    elif enabled and table:
        filtering = colored(symbol("ok") + " АКТИВНА", "green", "bold")
    elif enabled:
        filtering = colored(symbol("error") + " ТРЕБУЕТ ВОССТАНОВЛЕНИЯ", "red", "bold")
    else:
        filtering = colored(symbol("idle") + " ВЫКЛЮЧЕНА", "yellow", "bold")
    print()
    rule("─", style="blue")
    print(colored("  ОТЧЁТ О РАБОТЕ КОМПОНЕНТОВ", "blue", "bold"))
    print()
    field("Фильтрация", filtering)
    if table:
        table_status = status_mark(True, "ЗАГРУЖЕНА")
    elif enabled or pending:
        table_status = status_mark(False, bad="ОТСУТСТВУЕТ")
    else:
        table_status = colored(symbol("idle") + " не загружена — фильтрация выключена", "yellow")
    field("Таблица nftables", table_status)
    if enabled:
        startup = status_mark(service_enabled, "ВКЛЮЧЕНО", "ВЫКЛЮЧЕНО")
        updates = status_mark(timer_active, "АКТИВНО", "НЕАКТИВНО")
    else:
        startup = colored(symbol("idle") + " включится вместе с фильтрацией", "yellow")
        updates = colored(symbol("idle") + " включится вместе с фильтрацией", "yellow")
    field("Восстановление при старте", startup)
    field("Ежедневное обновление", updates)
    field("Внешние списки", f"{sum(len(x) for x in state['lists'].values())} сетей/адресов")
    field("Исключения", len(state['allow']))
    field("Журналирование блокировок", 'ВКЛЮЧЕНО' if state.get('logging') else 'ВЫКЛЮЧЕНО')
    field("Последнее обновление", format_updated(state.get('updated')))
    rule("─", style="blue")


def port_list(value):
    ports = sorted(set(int(x) for x in value.replace(',', ' ').split()))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Порты должны быть числами от 1 до 65535.")
    return ports


def port_number(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("порт должен быть целым числом") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("порт должен быть в диапазоне от 1 до 65535")
    return port


def ip_list(value):
    values = sorted(set(host(x) for x in value.replace(',', ' ').split()))
    if not values:
        raise ValueError("Укажите хотя бы один IP.")
    return values


def ask_yes(label):
    while True:
        answer = input(colored(label + " [Д/Н]: ", "yellow", "bold")).strip().lower()
        if answer in ("д", "да", "y", "yes"):
            return True
        if answer in ("н", "нет", "n", "no"):
            return False
        warn("Введите Д/Да/Y/Yes или Н/Нет/N/No.")


def brand_header():
    print()
    width = terminal_width()
    if width < 8:
        print_fit("ЧебурNET", "cyan")
        return
    left, right, bottom_left, bottom_right, side = ("╭", "╮", "╰", "╯", "│") if decorated() else ("+", "+", "+", "+", "|")
    inside = width - 4
    print(colored(left + symbol("light") * (width - 2) + right, "cyan"))
    for value, styles in [
        ("ЧебурNET · TRAFFIC CONTROL", ("cyan", "bold")),
        ("Версия " + VERSION, ("dim",)),
        ("Леонид Копысов · Telegram: @kopysovleonid", ("dim",)),
        ("GitHub: leonidkopysov", ("dim",)),
    ]:
        for line in textwrap.wrap(value, width=inside):
            print(colored(side, "cyan") + " " + pad_right(colored(line, *styles), inside) + " " + colored(side, "cyan"))
    print(colored(bottom_left + symbol("light") * (width - 2) + bottom_right, "cyan"))


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
    info("После проверки фильтрация будет включена автоматически.")
    warn("Держите доступ к консоли VPS до завершения проверки.")
    print()
    if not ask_yes("  Продолжить установку?"):
        raise ValueError("Установка отменена пользователем.")


def ask_value(label, candidate, validator):
    if candidate:
        info(label + ": " + candidate)
        if ask_yes("  Верно?"):
            return validator(candidate)
    while True:
        try:
            prompt = colored("  " + label + " (введите своё значение): ", "yellow", "bold")
            return validator(input(prompt).strip())
        except (ValueError, OSError):
            warn("Некорректное значение. Повторите ввод.")


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
        labels = value.split('.')
        if (len(value) > 253 or not labels or any(
                not re.fullmatch(r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)', label)
                for label in labels)):
            raise ValueError('Укажите IP или домен без https:// и пути.')
        warn('DNS домена может указывать на CDN, а не исходящий IP панели.')
        if not shutil.which('getent'):
            raise ValueError('Не найдена команда getent для безопасного поиска домена.')
        result = run('getent', 'ahosts', value, check=False, timeout=10)
        if result.returncode not in (0, 2):
            raise ValueError('Не удалось выполнить DNS-поиск домена.')
        addresses = []
        for line in result.stdout.splitlines():
            candidate = line.split(maxsplit=1)[0] if line.split() else ''
            try:
                addresses.append(host(candidate))
            except ValueError:
                continue
        addresses = sorted(set(addresses))
        info('Найдены адреса: ' + ', '.join(addresses))
        if not addresses or not ask_yes('  Это именно исходящие IP панели?'):
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
    info('IP SSH-клиента может принадлежать VPN, NAT или промежуточному серверу.')
    admins = ask_value('IP администратора', admin, ip_list)
    ports = ask_value('Порт SSH', port, port_list)
    panel = ask_value('Исходящие IP панели (или её домен для поиска)', panel_hint(), panel_input)
    allowed = sorted(set(admins + panel))
    info('Итог: SSH ' + ', '.join(map(str, ports)) + '; исключения IP: ' + ', '.join(allowed))
    if not ask_yes('  Установить с этими настройками?'):
        raise ValueError('Установка отменена. Настройки не записаны.')
    return ports, allowed


def preflight_install():
    """Reject obvious path conflicts before apt or other system changes begin."""
    if path_exists(STATE):
        load()
        return "existing"
    occupied = []
    for path in (BIN, SHORT_BIN, *(SYSTEMD / name for name in service_files())):
        if path_exists(path):
            occupied.append(str(path))
    if occupied:
        raise ValueError("Обнаружена незавершённая или чужая установка: "
                         + ", ".join(occupied) + ". Системные файлы не изменены.")
    if shutil.which("traffic-guard") or Path("/opt/trafficguard-manager.sh").exists():
        raise ValueError("Обнаружен TrafficGuard. Сначала удалите его штатным способом.")
    return "new"


def install(args):
    install_mode = preflight_install()
    if install_mode == "existing":
        state = load()
        warn("Компонент уже установлен. Проверяю и восстанавливаю его без изменения настроек.")
        result = repair(state, confirmed=True)
        if result:
            raise ValueError("Повторная установка завершилась, но самодиагностика нашла проблемы.")
        if not (ROOT / "enabled").exists():
            activate()
        ok("Повторная установка завершена; конфигурация сохранена, фильтрация включена.")
        return
    if present():
        raise ValueError("Таблица nftables с именем ЧебурNET уже существует. Автоперезапись запрещена.")
    ports, allow = install_inputs(args)
    state = dict(schema=1, ssh_ports=ports, allow=sorted(set(allow)), manual=[],
                 lists=fetch_lists(), updated=int(time.time()), logging=args.logging)
    run("nft", "-c", "-f", "-", data=render(state), timeout=300)
    root_created = not path_exists(ROOT)
    if not root_created:
        details = ROOT.lstat()
        if (not stat.S_ISDIR(details.st_mode) or ROOT.is_symlink()
                or details.st_uid != 0 or details.st_mode & 0o022):
            raise ValueError(f"Каталог {ROOT} существует, но небезопасен; установка остановлена.")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
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
    ok("Компонент установлен, конфигурация сохранена.")
    activate()


def activate():
    state = load()
    if (ROOT / "enabled").exists() or (ROOT / "pending").exists():
        raise ValueError("Фильтрация уже включена или предыдущая операция не завершена. "
                         "Выполните cheburnet-traffic-control status.")
    atomic(ROOT / "pending", str(time.time()))
    try:
        # The timer is only a crash-recovery guard; no user confirmation step.
        run("systemctl", "restart", UNIT + "-rollback.timer")
        apply(state)
        finish_activation()
    except BaseException:
        # Keep the guard armed if cleanup itself fails.
        disable()
        run("systemctl", "stop", UNIT + "-rollback.timer", check=False)
        raise
    ok("Фильтрация включена. Автовосстановление и обновление списков включены.")


def finish_activation():
    """Commit activation while holding the shared lock, including old installations."""
    if not present():
        raise ValueError("Таблица фильтрации отсутствует; включение не завершено.")
    atomic(ROOT / "enabled", "1\n")
    try:
        run("systemctl", "enable", UNIT + ".service")
        run("systemctl", "enable", "--now", UNIT + "-update.timer")
    except BaseException:
        (ROOT / "enabled").unlink(missing_ok=True)
        raise
    (ROOT / "pending").unlink(missing_ok=True)
    run("systemctl", "stop", UNIT + "-rollback.timer", check=False)


def disable(units=True):
    # Keep state markers intact if nftables removal fails, so diagnostics do not
    # incorrectly report a disabled filter while its table is still loaded.
    remove_table()
    (ROOT / "enabled").unlink(missing_ok=True)
    (ROOT / "pending").unlink(missing_ok=True)
    if units:
        run("systemctl", "disable", "--now", UNIT + "-update.timer", check=False)
        run("systemctl", "disable", UNIT + ".service", check=False)
    info("Фильтрация ЧебурNET выключена; остальные правила firewall не изменены.")


def file_is_secure(path, executable=False):
    try:
        details = path.lstat()
        mode = details.st_mode
        return (stat.S_ISREG(mode) and not path.is_symlink() and details.st_uid == 0
                and not mode & 0o022 and (not executable or bool(mode & 0o111)))
    except OSError:
        return False


def directory_is_secure(path):
    try:
        details = path.lstat()
        return (stat.S_ISDIR(details.st_mode) and not path.is_symlink()
                and details.st_uid == 0 and not details.st_mode & 0o022)
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

    try:
        system, version, architecture = platform_details()
        platform_ok = True
        platform_text = f"{system} {version}, {architecture}"
    except ValueError as exc:
        platform_ok = False
        platform_text = str(exc)
    add("Совместимость системы", platform_ok, platform_text)
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
        config_ok = (directory_is_secure(ROOT) and ROOT.stat().st_mode & 0o777 == 0o700 and
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
        add("Незавершённое включение", table and unit_state("is-active", UNIT + "-rollback.timer") == "active",
            "таймер отката активен")
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
    for name, item_ok, detail in items:
        mark = (colored(symbol("ok"), "green", "bold") if item_ok else
                colored(symbol("error"), "red", "bold"))
        print(f"  {mark} {name}: {detail}")
    failed = sum(not item_ok for _, item_ok, _ in items)
    print()
    if failed:
        err(f"Обнаружено проблем: {failed}. "
            "Выполните cheburnet-traffic-control repair.")
    else:
        ok("Все проверяемые компоненты работают штатно.")
    rule()
    return failed


def repair(state, confirmed=False):
    if (ROOT / "pending").exists():
        raise ValueError("Предыдущее включение не завершено. Выполните ctc off и повторите исправление.")
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
    ok("Восстановление завершено. Повторяю диагностику.")
    return print_diagnostics(state)


def print_status(state):
    print()
    rule("─", style="blue")
    print(colored("  СОСТОЯНИЕ", "blue", "bold"))
    print()
    field("Версия", VERSION)
    field("Таблица nftables", 'создана' if present() else 'отсутствует')
    field("Фильтрация", 'включена' if (ROOT / 'enabled').exists() else 'выключена')
    field("Операция включения", 'не завершена' if (ROOT / 'pending').exists() else 'нет незавершённых операций')
    field("Списки обновлены", format_updated(state.get('updated')))
    for name, entries in state["lists"].items():
        field(name, f"{len(entries)} записей")
    field("Порты SSH", ', '.join(map(str, state['ssh_ports'])))
    field("Исключения", ', '.join(state['allow']))
    field("Ручные блокировки", ', '.join(state['manual']) or '-')
    print()
    info("Полные правила: cheburnet-traffic-control rules")
    rule("─", style="blue")


def print_rules():
    print()
    rule()
    print(colored("  ПОЛНЫЕ ПРАВИЛА NFTABLES", "cyan", "bold"))
    rule()
    if not present():
        info("Таблица ЧебурNET сейчас не загружена.")
        return
    print(colored("  Ниже приведён неизменённый вывод nftables:", "dim"))
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
        run("systemctl", "stop", UNIT + "-update.service",
            UNIT + "-rollback.timer", UNIT + "-rollback.service",
            UNIT + ".service", check=False)
        for name in service_files():
            (SYSTEMD / name).unlink(missing_ok=True)
        if shortcut_valid():
            SHORT_BIN.unlink(missing_ok=True)
        BIN.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        ok("Удаление завершено: программа, короткая команда и службы удалены.")
        info("Конфигурация сохранена в " + str(ROOT))
    elif cmd in ("update", "ban", "unban", "allow", "disallow"):
        if (ROOT / "pending").exists():
            raise ValueError("Предыдущее включение не завершено. Выполните ctc off, затем ctc on.")
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
        ok(action)
        info("Исключения и SSH имеют приоритет над блокировками.")
        if cmd == "unban":
            info("Удалена только точная ручная блокировка. Для внешнего списка добавьте IP в исключения.")


def menu():
    while True:
        height = shutil.get_terminal_size((80, 24)).lines
        if decorated() and height >= 30:
            print("\033[2J\033[H", end="")
        brand_header()
        installed = STATE.exists()
        status = menu_status()
        if terminal_width() >= 40:
            print("  " + pad_right("Состояние", 14) + status)
        else:
            print_fit("Состояние: " + re.sub(r'\x1b\[[0-9;]*m', '', status).strip(), "dim")
        if installed:
            try:
                state = load()
                component_report(state)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                err("Отчёт недоступен: " + safe_label(exc))
        else:
            print()
            info("Компонент ещё не установлен.")
        print()
        print(colored("  ГЛАВНОЕ МЕНЮ", "magenta", "bold"))
        print()
        if not installed:
            menu_line("1", "Установить компонент и включить фильтрацию", "green")
        else:
            menu_section("Просмотр")
            menu_line("1", "Показать краткое состояние", "blue")
            menu_line("2", "Обновить три внешних списка", "blue")
            menu_line("11", "Самодиагностика и исправление", "magenta")
            menu_line("12", "Показать полные правила nftables", "blue")
            menu_line("13", "Показать последние журналы", "blue")
            menu_section("Списки")
            menu_line("3", "Добавить ручной бан IP или CIDR", "yellow")
            menu_line("4", "Снять точный ручной бан", "green")
            menu_line("5", "Добавить IP в исключения", "green")
            menu_line("6", "Удалить IP из исключений", "yellow")
            menu_section("Управление")
            menu_line("7", "Включить фильтрацию", "white")
            menu_line("9", "Выключить фильтрацию", "yellow")
            menu_line("10", "Удаление программы и служб", "red")
        menu_line("0", "Выход", "white")
        if installed:
            top_limit = 5 if height < 30 else 10
            try:
                top(limit=top_limit)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                print()
                err(f"Топ-{top_limit} временно недоступен: " + safe_label(exc))
        print()
        rule("─", style="cyan")
        choice = input(colored("  Выберите действие: ", "yellow", "bold")).strip()
        if choice == "0":
            return
        command = ("install" if not installed and choice == "1" else
                   {"1": "status", "2": "update", "3": "ban", "4": "unban",
                    "5": "allow", "6": "disallow", "7": "activate",
                    "9": "disable", "10": "uninstall", "11": "check",
                    "12": "rules", "13": "logs"}.get(choice) if installed else None)
        if not command:
            continue
        args = [command]
        if command in ("ban", "unban", "allow", "disallow"):
            args.append(input(colored("  IP (для ручного бана также CIDR): ",
                                      "yellow", "bold")).strip())
        if command == "uninstall":
            if not ask_yes("  Выполнить удаление программы и служб?"):
                continue
            args.append("--yes")
        try:
            problems = main(args)
            if command == "check" and problems and ask_yes("  Исправить обнаруженные проблемы?"):
                main(["repair", "--yes"])
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            err(str(exc))
        if command == "uninstall":
            return
        if command == "install":
            continue
        input(colored("  Нажмите Enter, чтобы вернуться в меню: ", "yellow", "bold"))


def normalize_argv(argv):
    values = list(argv)
    if values and values[0] in COMMAND_ALIASES:
        values[0] = COMMAND_ALIASES[values[0]]
    return values


class RussianArgumentParser(argparse.ArgumentParser):
    """Argparse shell with Russian headings and explicit Russian help option."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("add_help", False)
        super().__init__(*args, **kwargs)
        self.add_argument("-h", "--help", action="help", help="показать эту справку и выйти")
        self._positionals.title = "позиционные аргументы"
        self._optionals.title = "параметры"

    def format_usage(self):
        return super().format_usage().replace("usage:", "использование:", 1)

    def format_help(self):
        return (super().format_help()
                .replace("usage:", "использование:", 1)
                .replace("options:", "параметры:", 1)
                .replace("positional arguments:", "позиционные аргументы:", 1))

    def error(self, message):
        translations = {
            "the following arguments are required:": "необходимо указать:",
            "unrecognized arguments:": "неизвестные параметры:",
            "invalid choice:": "недопустимый вариант:",
            "argument ": "аргумент ",
            "(choose from ": "(доступно: ",
            "expected one argument": "ожидается одно значение",
        }
        for source, target in translations.items():
            message = message.replace(source, target)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: ошибка: {message}\n")


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
    parser = RussianArgumentParser(
        prog="cheburnet-traffic-control",
        usage="%(prog)s [--version] КОМАНДА [ПАРАМЕТРЫ]",
        description="ЧебурNET Traffic Control — управление фильтрацией входящего трафика.")
    parser.add_argument("--version", action="version", version=VERSION,
                        help="показать номер версии и выйти")
    subs = parser.add_subparsers(dest="command", required=True, title="команды", metavar="КОМАНДА")
    inst = subs.add_parser("install", prog=parser.prog + " install", usage="%(prog)s [ПАРАМЕТРЫ]",
                           help="установить компонент и включить фильтрацию")
    inst.add_argument("--ssh-port", action="append", type=port_number, metavar="ПОРТ",
                      help="порт SSH; параметр можно указать несколько раз")
    inst.add_argument("--allow", action="append", default=[], metavar="IP",
                      help="добавить IP в исключения; параметр можно указать несколько раз")
    inst.add_argument("--yes", action="store_true",
                      help="подтвердить автоматическую установку без вопросов")
    inst.add_argument("--no-logging", action="store_false", dest="logging",
                      help="отключить журналирование блокировок")
    inst.set_defaults(logging=True)
    top_parser = subs.add_parser("top", prog=parser.prog + " top", usage="%(prog)s [--no-resolve]",
                                 help="показать топ-10 заблокированных IP")
    top_parser.add_argument("--no-resolve", action="store_true",
                            help="не запрашивать сведения об организациях через RDAP")
    status_parser = subs.add_parser("status", prog=parser.prog + " status", usage="%(prog)s [--json]",
                                    help="показать краткий отчёт")
    status_parser.add_argument("--json", action="store_true",
                               help="вывести неизменённый машинный отчёт JSON")
    command_help = {
        "rules": "показать полные правила nftables", "logs": "показать последние журналы",
        "check": "выполнить самодиагностику",
        "activate": "включить фильтрацию, автовосстановление и обновление списков",
        "disable": "выключить фильтрацию", "restore": "восстановить правила из локальной копии",
        "rollback": "выполнить аварийный откат", "update": "обновить три внешних списка",
    }
    for cmd, help_text in command_help.items():
        subs.add_parser(cmd, prog=parser.prog + " " + cmd, usage="%(prog)s", help=help_text)
    repair_parser = subs.add_parser("repair", prog=parser.prog + " repair", usage="%(prog)s [--yes]",
                                    help="исправить обнаруженные проблемы")
    repair_parser.add_argument("--yes", action="store_true",
                               help="подтвердить автоматическое восстановление без вопросов")
    address_help = {
        "ban": "добавить ручную блокировку", "unban": "удалить точную ручную блокировку",
        "allow": "добавить IP в исключения", "disallow": "удалить IP из исключений",
    }
    for cmd, help_text in address_help.items():
        subs.add_parser(cmd, prog=parser.prog + " " + cmd, usage="%(prog)s АДРЕС", help=help_text).add_argument(
            "address", metavar="АДРЕС", help="IP или допустимый CIDR")
    uninstall_parser = subs.add_parser("uninstall", prog=parser.prog + " uninstall", usage="%(prog)s [--yes]",
                                       help="удалить программу и службы")
    uninstall_parser.add_argument("--yes", action="store_true",
                                  help="подтвердить удаление без дополнительного вопроса")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError("Запуск только от root.")
    if args.command == "install":
        preflight_install()
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
    with exclusive_lock():
        result = execute(args)
    if args.command == "install" and direct_invocation and sys.stdin.isatty():
        menu()
    return result


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(file=sys.stderr)
        message("info", "Операция прервана пользователем.", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print(file=sys.stderr)
        err("Ввод завершён до окончания операции.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        err(str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            if exc.stderr:
                print("  " + exc.stderr.strip(), file=sys.stderr)
        sys.exit(1)
