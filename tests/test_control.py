import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import io
from argparse import Namespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("control", Path(__file__).parents[1] / "cheburnet-traffic-control.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class ControlTests(unittest.TestCase):
    def state(self):
        return dict(ssh_ports=[22222], allow=["198.51.100.9", "2001:db8::1"],
                    lists={"test": ["198.51.100.0/24", "2001:db8::/32"]}, manual=[])

    def test_canonical(self):
        self.assertEqual(c.networks("1.2.3.4/24 # test\n"), ["1.2.3.0/24"])

    def test_collapse(self):
        self.assertEqual(c.networks("1.2.3.0/25\n1.2.3.128/25\n1.2.3.0/25"), ["1.2.3.0/24"])

    def test_empty(self):
        with self.assertRaises(ValueError):
            c.networks("# empty\n")

    def test_invalid(self):
        for value in ("<html>", "1.2.3.4; flush ruleset", "0.0.0.0/0", "::/0", "999.1.1.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.networks(value)

    def test_ipv6(self):
        self.assertEqual(c.networks("2001:db8::1"), ["2001:db8::1/128"])

    def test_priority(self):
        rules = c.render(self.state())
        self.assertLess(rules.index("tcp dport"), rules.index("counter drop"))
        self.assertLess(rules.index("saddr @allow4"), rules.index("saddr @block4"))
        self.assertIn("ip6 saddr @block6 counter drop", rules)

    def test_scope(self):
        rules = c.render(self.state(), True)
        self.assertTrue(rules.startswith("delete table inet cheburnet_tc\n"))
        for forbidden in ("flush ruleset", "hook output", "hook forward", "ufw", "SCANNERS"):
            self.assertNotIn(forbidden, rules)

    def test_bad_ports(self):
        for ports in ([], [0], [65536]):
            state = self.state()
            state["ssh_ports"] = ports
            with self.assertRaises(ValueError):
                c.render(state)

    def test_logging_limited_not_drop_limited(self):
        state = self.state()
        state["logging"] = True
        lines = c.render(state).splitlines()
        self.assertEqual(sum("log prefix" in x for x in lines), 2)
        self.assertTrue(all("limit" not in x for x in lines if "drop" in x))

    def test_all_sources_or_failure(self):
        with patch.object(c, "download", side_effect=[["1.2.3.0/24"], ValueError("offline")]):
            with self.assertRaises(ValueError):
                c.fetch_lists()

    def test_syntax_checked_before_apply(self):
        with patch.object(c, "present", return_value=False), patch.object(c, "run", side_effect=ValueError("bad")) as run:
            with self.assertRaises(ValueError):
                c.apply(self.state())
            self.assertEqual(run.call_count, 1)
            self.assertIn("-c", run.call_args.args)

    def test_nft_apply_uses_extended_timeout(self):
        with patch.object(c, "present", return_value=False), patch.object(c, "run") as run:
            c.apply(self.state())
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call.kwargs["timeout"] == 300 for call in run.call_args_list))

    def test_atomic(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            c.atomic(path, json.dumps(self.state()))
            self.assertEqual(json.loads(path.read_text()), self.state())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_disk_failure_reverts_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "enabled").touch()
            with patch.object(c, "ROOT", root), patch.object(c, "apply") as apply, patch.object(c, "save", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    c.commit({"new": True}, {"old": True})
                self.assertEqual(apply.call_args_list[1].args, ({"old": True},))

    def test_https_redirect(self):
        with self.assertRaises(ValueError):
            c.HTTPSOnly().redirect_request(None, None, 302, "", {}, "http://example.com")

    def test_top_only_our_logs(self):
        lines = [json.dumps({"MESSAGE": x}) for x in
                 ("CBTC4 IN=eth0 SRC=1.2.3.4 DST=2.3.4.5", "CBTC4 SRC=1.2.3.4 ",
                  "OTHER SRC=5.6.7.8", "CBTC6 SRC=2001:db8::1 DST=::1", "CBTC4 SRC=999.1.1.1 ")]
        self.assertEqual(c.journal_top("\n".join(lines)), [("1.2.3.4", 2), ("2001:db8::1", 1)])

    def test_top_accepts_empty_journal(self):
        result = c.subprocess.CompletedProcess(('journalctl',), 1, '', '')
        output = io.StringIO()
        with patch.object(c, 'run', return_value=result), patch('sys.stdout', output):
            c.top(resolve=False)
        self.assertIn('заблокированных обращений пока нет', output.getvalue())

    def test_log_report_accepts_empty_journals(self):
        output = io.StringIO()
        with patch.object(c, 'journal_output', return_value=''), patch('sys.stdout', output):
            c.print_logs()
        self.assertIn('За последние 24 часа записей нет', output.getvalue())
        self.assertIn('За последние 7 дней записей нет', output.getvalue())

    def test_rdap_network_fallback(self):
        self.assertEqual(c.rdap_label({"name": "EXAMPLE-NET"}), "EXAMPLE-NET")

    def test_rdap_owner(self):
        self.assertEqual(c.rdap_label({"entities": [{"roles": ["registrant"],
            "vcardArray": ["vcard", [["org", {}, "text", "Example Hosting"]]]}]}), "Example Hosting")

    def test_rdap_batch_uses_cache_and_resolves_missing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = {"1.1.1.1": {"time": c.time.time(), "label": "Cloudflare"}}
            (root / "rdap-cache.json").write_text(json.dumps(cache), encoding="utf-8")
            with patch.object(c, "ROOT", root), patch.object(c, "rdap_lookup", return_value="Google") as lookup:
                labels = c.lookup_many(["1.1.1.1", "8.8.8.8"])
            self.assertEqual(labels, {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google"})
            lookup.assert_called_once_with("8.8.8.8")

    def test_interactive_accept(self):
        with patch.object(c.sys.stdin, 'isatty', return_value=True), patch.dict(c.os.environ, {'SSH_CONNECTION': '1.2.3.4 50000 5.6.7.8 2222'}), patch.object(c, 'panel_hint', return_value='9.8.7.6'), patch('builtins.input', side_effect=['д', 'д', 'д', 'д']):
            self.assertEqual(c.install_inputs(Namespace(ssh_port=None, allow=[])), ([2222], ['1.2.3.4', '9.8.7.6']))

    def test_rejected_hints_not_retained(self):
        with patch.object(c.sys.stdin, 'isatty', return_value=True), patch.dict(c.os.environ, {'SSH_CONNECTION': '1.2.3.4 50000 5.6.7.8 2222'}), patch.object(c, 'panel_hint', return_value='9.8.7.6'), patch('builtins.input', side_effect=['н', '8.8.8.8', 'н', '22', 'н', '1.1.1.1', 'д']):
            self.assertEqual(c.install_inputs(Namespace(ssh_port=None, allow=[])), ([22], ['1.1.1.1', '8.8.8.8']))

    def test_no_terminal(self):
        with patch.object(c.sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
            c.install_inputs(Namespace(ssh_port=None, allow=[]))

    def test_explicit_flags_not_augmented(self):
        with patch.dict(c.os.environ, {'SSH_CONNECTION': '9.9.9.9 123 5.5.5.5 5555'}):
            self.assertEqual(c.install_inputs(Namespace(ssh_port=[22], allow=['1.1.1.1'])), ([22], ['1.1.1.1']))

    def test_invalid_then_valid(self):
        with patch('builtins.input', side_effect=['65536', '22']):
            self.assertEqual(c.ask_value('SSH', '', c.port_list), [22])

    def test_domain_requires_confirmation(self):
        with patch.object(c.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('1.2.3.4', 0))]), patch('builtins.input', return_value='н'), self.assertRaises(ValueError):
            c.panel_input('panel.example.com')

    def test_vision_field_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            c.atomic(path, json.dumps({'panel_ips': '1.1.1.1 8.8.8.8', 'secret': 'never-print'}))
            with patch.object(Path, 'stat') as stat:
                stat.return_value.st_uid = 0
                stat.return_value.st_mode = 0o100600
                stat.return_value.st_size = 100
                self.assertEqual(c.panel_hint(path), '1.1.1.1 8.8.8.8')

    def test_color_disabled_for_pipe(self):
        with patch.object(c.sys.stdout, 'isatty', return_value=False):
            self.assertEqual(c.colored('Тест', 'red', 'bold'), 'Тест')

    def test_no_color_environment(self):
        with patch.object(c.sys.stdout, 'isatty', return_value=True), patch.dict(c.os.environ, {'NO_COLOR': '1'}):
            self.assertEqual(c.colored('Тест', 'green'), 'Тест')

    def test_color_enabled_for_terminal(self):
        with patch.object(c.sys.stdout, 'isatty', return_value=True), patch.dict(c.os.environ, {}, clear=True):
            self.assertIn('\033[92m', c.colored('Тест', 'green'))

    def test_vertical_menu_before_install(self):
        output = io.StringIO()
        with patch.object(c.sys.stdout, 'isatty', return_value=False), patch.object(c, 'STATE') as state, patch('builtins.input', return_value='0'), patch('sys.stdout', output):
            state.exists.return_value = False
            c.menu()
        text = output.getvalue()
        self.assertIn('Тестовая версия', text)
        self.assertIn('[ 1]  Установить компонент', text)
        self.assertNotIn('[10]  Удалить компонент', text)
        self.assertNotIn('\033[', text)

    def test_vertical_menu_after_install(self):
        output = io.StringIO()
        with patch.object(c.sys.stdout, 'isatty', return_value=False), patch.object(c, 'STATE') as state, \
             patch.object(c, 'load', return_value=self.state()), \
             patch.object(c, 'component_report', side_effect=lambda value: print('ОТЧЁТ КОМПОНЕНТОВ')), \
             patch.object(c, 'top', side_effect=lambda: print('ТОП-10 ПРОВЕРКА')), \
             patch('builtins.input', return_value='0'), patch('sys.stdout', output):
            state.exists.return_value = True
            c.menu()
        text = output.getvalue()
        self.assertIn('[ 1]  Показать краткое состояние', text)
        self.assertIn('[10]  Удалить компонент', text)
        self.assertIn('[11]  Самодиагностика', text)
        self.assertLess(text.index('ГЛАВНОЕ МЕНЮ'), text.index('ТОП-10 ПРОВЕРКА'))

    def test_short_command_aliases(self):
        self.assertEqual(c.normalize_argv(['s']), ['status'])
        self.assertEqual(c.normalize_argv(['on']), ['activate'])
        self.assertEqual(c.normalize_argv(['fix', '--yes']), ['repair', '--yes'])
        self.assertEqual(c.normalize_argv(['l']), ['logs'])

    def test_install_confirmation_precedes_dependencies(self):
        with patch.object(c.os, 'geteuid', return_value=0), \
             patch.object(c, 'confirm_install_start', side_effect=ValueError('отмена')), \
             patch.object(c, 'ensure_dependencies') as dependencies, self.assertRaisesRegex(ValueError, 'отмена'):
            c.main(['install'])
        dependencies.assert_not_called()

    def test_menu_requires_root_before_opening(self):
        with patch.object(c.sys.stdin, 'isatty', return_value=True), patch.object(c.os, 'geteuid', return_value=1000), patch.object(c, 'menu') as menu, self.assertRaises(ValueError):
            c.main([])
        menu.assert_not_called()

    def test_dependency_error_is_value_error_not_parser_exit(self):
        with patch.object(c.os, 'geteuid', return_value=0), patch.object(c, 'ensure_dependencies', side_effect=ValueError('нет nft')), self.assertRaisesRegex(ValueError, 'нет nft'):
            c.main(['status'])

    def test_restore_pending_does_not_manage_systemd_units(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'pending').touch()
            with patch.object(c, 'ROOT', root), patch.object(c, 'load', return_value=self.state()), patch.object(c, 'disable') as disable:
                c.execute(Namespace(command='restore'))
            disable.assert_called_once_with(units=False)

    def test_failed_install_removes_partial_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, systemd = base / 'state', base / 'systemd'
            systemd.mkdir()
            binary, short, state_file = base / 'bin', base / 'ctc', root / 'state.json'

            def fake_run(*args, **kwargs):
                if args == ('systemctl', 'daemon-reload') and kwargs.get('check', True):
                    raise OSError('daemon-reload failed')

            lists = {'test': ['198.51.100.0/24']}
            with patch.object(c, 'ROOT', root), patch.object(c, 'STATE', state_file), \
                 patch.object(c, 'BIN', binary), patch.object(c, 'SHORT_BIN', short), \
                 patch.object(c, 'SYSTEMD', systemd), \
                 patch.object(c, 'present', return_value=False), \
                 patch.object(c, 'install_inputs', return_value=([22], ['198.51.100.9'])), \
                 patch.object(c, 'fetch_lists', return_value=lists), \
                 patch.object(c, 'run', side_effect=fake_run), self.assertRaises(OSError):
                c.install(Namespace(logging=True))
            self.assertFalse(binary.exists())
            self.assertFalse(short.exists())
            self.assertFalse(state_file.exists())
            self.assertFalse(any((systemd / name).exists() for name in c.service_files()))

    def test_shortcut_points_to_main_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            binary, short = base / 'control', base / 'ctc'
            binary.touch()
            with patch.object(c, 'BIN', binary), patch.object(c, 'SHORT_BIN', short):
                c.write_shortcut()
                self.assertTrue(c.shortcut_valid())

    def test_compact_status_does_not_dump_rules(self):
        output = io.StringIO()
        with patch.object(c, 'component_report'), patch('sys.stdout', output):
            c.print_status(self.state())
        text = output.getvalue()
        self.assertIn('НАСТРОЙКИ', text)
        self.assertIn('Полные правила: ctc r', text)
        self.assertNotIn('table inet', text)

    def test_systemd_descriptions_are_russian(self):
        self.assertTrue(all('Description=ЧебурNET' in body for body in c.service_files().values()))

    def test_repair_refreshes_lists_and_creates_shortcut(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, systemd = base / 'state', base / 'systemd'
            root.mkdir()
            systemd.mkdir()
            state_file, binary, short = root / 'state.json', base / 'control', base / 'ctc'
            state_file.write_text('{}', encoding='utf-8')
            (root / 'enabled').touch()
            state = dict(self.state(), lists={'test': ['198.51.100.0/24']}, updated=1, logging=True)
            refreshed = {name: ['198.51.100.0/24'] for name in c.SOURCES}
            with patch.object(c, 'ROOT', root), patch.object(c, 'STATE', state_file), \
                 patch.object(c, 'BIN', binary), patch.object(c, 'SHORT_BIN', short), \
                 patch.object(c, 'SYSTEMD', systemd), patch.object(c, 'fetch_lists', return_value=refreshed) as fetch, \
                 patch.object(c, 'commit') as commit, patch.object(c, 'apply') as apply, \
                 patch.object(c, 'run') as run, patch.object(c, 'print_diagnostics', return_value=0):
                self.assertEqual(c.repair(state, confirmed=True), 0)
                self.assertTrue(c.shortcut_valid())
            fetch.assert_called_once_with()
            commit.assert_called_once()
            apply.assert_called_once()
            self.assertIn(('systemctl', 'enable', c.UNIT + '.service'), [call.args for call in run.call_args_list])
            self.assertNotIn(('systemctl', 'enable', '--now', c.UNIT + '.service'), [call.args for call in run.call_args_list])

    def test_os_release(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'os-release'
            path.write_text('ID="ubuntu"\nID_LIKE=debian\n# COMMENT=x\n')
            self.assertEqual(c.os_release(path), {'ID': 'ubuntu', 'ID_LIKE': 'debian'})

    def test_missing_packages(self):
        with patch.object(c.shutil, 'which', return_value=None), patch.object(c, 'CA_CERT') as ca_cert:
            ca_cert.is_file.return_value = False
            self.assertEqual(c.missing_packages(), ['nftables', 'ca-certificates'])

    def test_dependencies_do_not_call_apt_when_present(self):
        with patch.object(c, 'missing_packages', return_value=[]), patch.object(c.shutil, 'which', return_value='/bin/tool'), patch.object(c.Path, 'is_dir', return_value=True), patch.object(c, 'apt_install') as apt:
            c.ensure_dependencies(auto_install=True)
            apt.assert_not_called()

    def test_dependencies_install_only_missing(self):
        with patch.object(c, 'missing_packages', side_effect=[['nftables'], []]), patch.object(c, 'apt_install') as apt, patch.object(c.shutil, 'which', return_value='/bin/tool'), patch.object(c.Path, 'is_dir', return_value=True):
            c.ensure_dependencies(auto_install=True)
            apt.assert_called_once_with(['nftables'])

    def test_dependencies_without_auto_install(self):
        with patch.object(c, 'missing_packages', return_value=['nftables']), self.assertRaises(ValueError):
            c.ensure_dependencies(auto_install=False)

    def test_apt_rejects_unsupported_os(self):
        with patch.object(c, 'os_release', return_value={'ID': 'fedora'}), patch.object(c.shutil, 'which', return_value='/usr/bin/apt-get'), patch.object(c.subprocess, 'run') as run, self.assertRaises(ValueError):
            c.apt_install(['nftables'])
        run.assert_not_called()

    def test_apt_commands(self):
        with patch.object(c, 'os_release', return_value={'ID': 'debian'}), patch.object(c.shutil, 'which', return_value='/usr/bin/apt-get'), patch.object(c.subprocess, 'run') as run:
            c.apt_install(['nftables', 'ca-certificates'])
        self.assertEqual(run.call_args_list[0].args[0], ['apt-get', 'update'])
        self.assertEqual(run.call_args_list[1].args[0][-2:], ['nftables', 'ca-certificates'])


if __name__ == "__main__":
    unittest.main()
