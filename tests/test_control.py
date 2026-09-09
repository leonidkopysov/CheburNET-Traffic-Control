import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
