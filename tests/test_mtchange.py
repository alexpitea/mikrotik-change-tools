"""Tests for mtchange. They run against an in-memory stand-in for the RouterOS
API, so no router and no network are needed."""

import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mtchange  # noqa: E402


class FakeResource:
    def __init__(self, path, rows, log):
        self.path = path
        self.rows = rows
        self.log = log

    def get(self):
        return [dict(row) for row in self.rows]

    def set(self, id=None, **params):
        self.log.append(("set", self.path))
        if id is None:
            if not self.rows:
                self.rows.append({})
            self.rows[0].update(params)
        else:
            next(row for row in self.rows if row["id"] == id).update(params)

    def add(self, **params):
        self.log.append(("add", self.path))
        row = dict(params)
        row["id"] = "*%X" % (len(self.rows) + 1)
        self.rows.append(row)

    def call(self, name, params):
        self.log.append((name, self.path))


class FakeApi:
    """Only the paths given at construction exist, like a router without some
    packages installed."""

    def __init__(self, data):
        self.log = []
        self.resources = {path: FakeResource(path, rows, self.log) for path, rows in data.items()}

    def get_resource(self, path):
        if path not in self.resources:
            raise RuntimeError("no such command prefix")
        return self.resources[path]


def router_with_two_networks():
    return FakeApi({
        "/system/backup": [],
        "/ip/dhcp-server/network": [
            {"id": "*1", "address": "10.0.10.0/24", "dns-server": "10.0.10.1,1.1.1.1"},
            {"id": "*2", "address": "10.0.20.0/24", "dns-server": "10.0.20.1"},
            {"id": "*3", "address": "10.0.30.0/24", "dns-server": "1.1.1.1"},
        ],
        "/system/logging": [],
        "/system/logging/action": [],
        "/ip/traffic-flow": [{"enabled": "false"}],
        "/ip/traffic-flow/target": [],
    })


DNS_ENTRIES = [
    {"network": "10.0.10.0/24", "new": "10.0.10.53,10.0.10.1", "old": "10.0.10.1,1.1.1.1"},
    {"network": "10.0.20.0/24", "new": "10.0.10.53,10.0.20.1", "old": "10.0.20.1"},
]

MONITORING = {
    "syslog": {
        "action_name": "siem",
        "remote": "10.0.10.53",
        "port": 514,
        "src_address": "10.0.10.1",
        "topics": ["critical,error,warning", "info,!debug,!packet"],
    },
    "netflow": {"target": "10.0.10.53", "port": 2055, "interfaces": "vlan10,vlan20", "sampling_interval": 100},
}


def dns_server(api, network):
    rows = api.get_resource("/ip/dhcp-server/network").get()
    return next(row for row in rows if row["address"] == network)["dns-server"]


class DhcpDnsTests(unittest.TestCase):
    def test_apply_changes_only_configured_networks(self):
        api = router_with_two_networks()
        plan = mtchange.plan_dhcp_dns(api, DNS_ENTRIES, "new")
        self.assertEqual([step["network"] for step in plan], ["10.0.10.0/24", "10.0.20.0/24"])

        mtchange.apply_dhcp_dns(api, plan)
        self.assertEqual(dns_server(api, "10.0.10.0/24"), "10.0.10.53,10.0.10.1")
        self.assertEqual(dns_server(api, "10.0.20.0/24"), "10.0.10.53,10.0.20.1")
        self.assertEqual(dns_server(api, "10.0.30.0/24"), "1.1.1.1")  # the guest network is not touched

    def test_apply_twice_does_nothing_the_second_time(self):
        api = router_with_two_networks()
        mtchange.apply_dhcp_dns(api, mtchange.plan_dhcp_dns(api, DNS_ENTRIES, "new"))
        self.assertEqual(mtchange.plan_dhcp_dns(api, DNS_ENTRIES, "new"), [])

    def test_rollback_restores_the_old_servers(self):
        api = router_with_two_networks()
        mtchange.apply_dhcp_dns(api, mtchange.plan_dhcp_dns(api, DNS_ENTRIES, "new"))
        mtchange.apply_dhcp_dns(api, mtchange.plan_dhcp_dns(api, DNS_ENTRIES, "old"))
        self.assertEqual(dns_server(api, "10.0.10.0/24"), "10.0.10.1,1.1.1.1")
        self.assertEqual(dns_server(api, "10.0.20.0/24"), "10.0.20.1")

    def test_missing_network_stops_before_any_change(self):
        api = router_with_two_networks()
        entries = DNS_ENTRIES + [{"network": "10.0.99.0/24", "new": "10.0.10.53", "old": "1.1.1.1"}]
        with self.assertRaises(mtchange.ChangeError):
            mtchange.plan_dhcp_dns(api, entries, "new")
        self.assertEqual(dns_server(api, "10.0.10.0/24"), "10.0.10.1,1.1.1.1")
        self.assertEqual(api.log, [])


class MonitoringTests(unittest.TestCase):
    def test_empty_router_gets_action_rules_flow_and_target(self):
        api = router_with_two_networks()
        plan = mtchange.plan_syslog(api, MONITORING["syslog"]) + mtchange.plan_netflow(api, MONITORING["netflow"])
        self.assertEqual(
            [(step["op"], step["path"]) for step in plan],
            [
                ("add", "/system/logging/action"),
                ("add", "/system/logging"),
                ("add", "/system/logging"),
                ("set", "/ip/traffic-flow"),
                ("add", "/ip/traffic-flow/target"),
            ],
        )
        mtchange.apply_plan(api, plan)

        action = api.get_resource("/system/logging/action").get()[0]
        self.assertEqual((action["remote"], action["remote-port"], action["src-address"]), ("10.0.10.53", "514", "10.0.10.1"))
        target = api.get_resource("/ip/traffic-flow/target").get()[0]
        self.assertEqual((target["dst-address"], target["port"], target["version"]), ("10.0.10.53", "2055", "9"))
        flow = api.get_resource("/ip/traffic-flow").get()[0]
        self.assertEqual((flow["enabled"], flow["interfaces"], flow["sampling-interval"]), ("true", "vlan10,vlan20", "100"))

    def test_second_run_finds_nothing_to_change(self):
        api = router_with_two_networks()
        mtchange.apply_plan(api, mtchange.plan_syslog(api, MONITORING["syslog"]) + mtchange.plan_netflow(api, MONITORING["netflow"]))
        self.assertEqual(mtchange.plan_syslog(api, MONITORING["syslog"]), [])
        self.assertEqual(mtchange.plan_netflow(api, MONITORING["netflow"]), [])

    def test_only_the_different_field_is_changed(self):
        api = router_with_two_networks()
        mtchange.apply_plan(api, mtchange.plan_syslog(api, MONITORING["syslog"]))
        api.get_resource("/system/logging/action").rows[0]["remote"] = "10.0.10.99"
        plan = mtchange.plan_syslog(api, MONITORING["syslog"])
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["params"], {"remote": "10.0.10.53"})

    def test_disabled_rule_is_enabled_again(self):
        api = router_with_two_networks()
        mtchange.apply_plan(api, mtchange.plan_syslog(api, MONITORING["syslog"]))
        api.get_resource("/system/logging").rows[0]["disabled"] = "true"
        plan = mtchange.plan_syslog(api, MONITORING["syslog"])
        self.assertEqual([(step["op"], step["params"]) for step in plan], [("set", {"disabled": "false"})])


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.config = {
            "router": {"host": "192.0.2.1"},
            "snapshot_dir": self.folder.name,
            "dhcp_dns": DNS_ENTRIES,
            "monitoring": MONITORING,
        }
        self.lines = []

    def run_command(self, api, **arguments):
        return mtchange.execute(api, self.config, argparse.Namespace(**arguments), out=self.lines.append)

    def files(self):
        return sorted(path.name for path in Path(self.folder.name).iterdir())

    def test_backup_is_taken_before_the_first_change(self):
        api = router_with_two_networks()
        self.assertEqual(self.run_command(api, command="dns", action="apply", dry_run=False), 0)
        self.assertEqual(api.log[0], ("save", "/system/backup"))
        self.assertEqual([entry for entry in api.log if entry[0] == "set"], [("set", "/ip/dhcp-server/network")] * 2)

        names = self.files()
        self.assertTrue(any(name.startswith("before-dns-apply-") for name in names))
        self.assertTrue(any(name.startswith("after-dns-apply-") for name in names))
        self.assertIn("ROLLBACK-dhcp-dns.txt", names)

    def test_dry_run_changes_nothing_and_writes_nothing(self):
        api = router_with_two_networks()
        self.assertEqual(self.run_command(api, command="dns", action="apply", dry_run=True), 0)
        self.assertEqual(api.log, [])
        self.assertEqual(self.files(), [])
        self.assertEqual(dns_server(api, "10.0.10.0/24"), "10.0.10.1,1.1.1.1")
        self.assertTrue(any("10.0.10.0/24" in line for line in self.lines))

    def test_no_backup_when_there_is_nothing_to_change(self):
        api = router_with_two_networks()
        self.run_command(api, command="dns", action="apply", dry_run=False)
        api.log.clear()
        self.run_command(api, command="dns", action="apply", dry_run=False)
        self.assertEqual(api.log, [])

    def test_credentials_never_reach_the_files(self):
        os.environ["MT_USER"] = "secret-user-for-test"
        os.environ["MT_PASS"] = "secret-pass-for-test"
        self.addCleanup(os.environ.pop, "MT_USER", None)
        self.addCleanup(os.environ.pop, "MT_PASS", None)

        api = router_with_two_networks()
        self.run_command(api, command="dns", action="apply", dry_run=False)
        self.run_command(api, command="monitoring", action="apply", dry_run=False)
        for path in Path(self.folder.name).iterdir():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("secret-user-for-test", text)
            self.assertNotIn("secret-pass-for-test", text)

    def test_snapshot_survives_a_missing_path(self):
        api = router_with_two_networks()  # has no /ip/dns
        self.run_command(api, command="status")
        snapshot = json.loads(next(Path(self.folder.name).glob("status-*.json")).read_text(encoding="utf-8"))
        self.assertIn("error", snapshot["/ip/dns"])
        self.assertEqual(len(snapshot["/ip/dhcp-server/network"]), 3)

    def test_rollback_note_has_one_command_per_network(self):
        note = mtchange.rollback_note(DNS_ENTRIES)
        self.assertEqual(note.count("/ip dhcp-server network set"), 2)
        self.assertIn('address="10.0.20.0/24"] dns-server=10.0.20.1', note)


class ConfigTests(unittest.TestCase):
    def test_config_without_host_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text('{"router": {}}', encoding="utf-8")
            with self.assertRaises(mtchange.ChangeError):
                mtchange.load_config(path)

    def test_example_config_loads(self):
        example = Path(__file__).resolve().parent.parent / "config.example.json"
        config = mtchange.load_config(example)
        self.assertEqual(config["router"]["host"], "192.0.2.1")
        self.assertTrue(config["dhcp_dns"])


if __name__ == "__main__":
    unittest.main()
