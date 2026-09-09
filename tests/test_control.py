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

    def test_rdap_network_fallback(self):
        self.assertEqual(c.rdap_label({"name": "EXAMPLE-NET"}), "EXAMPLE-NET")

    def test_rdap_owner(self):
        self.assertEqual(c.rdap_label({"entities": [{"roles": ["registrant"],
            "vcardArray": ["vcard", [["org", {}, "text", "Example Hosting"]]]}]}), "Example Hosting")

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

    def test_vertical_menu(self):
        output = io.StringIO()
        with patch.object(c.sys.stdout, 'isatty', return_value=False), patch.object(c, 'STATE') as state, patch('builtins.input', return_value='0'), patch('sys.stdout', output):
            state.exists.return_value = False
            c.menu()
        text = output.getvalue()
        self.assertIn('ТЕСТОВАЯ ВЕРСИЯ', text)
        self.assertIn('[ 1]  Показать состояние', text)
        self.assertIn('[10]  Удалить компонент', text)
        self.assertNotIn('\033[', text)


if __name__ == "__main__":
    unittest.main()
