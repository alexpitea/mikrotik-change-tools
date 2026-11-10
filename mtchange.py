"""Safe configuration changes on a MikroTik router through the RouterOS API.

Every command that changes the router first saves a binary backup on the
router and a JSON snapshot on this computer, then applies the change, then
saves a second snapshot. Changes are idempotent and can be previewed with
--dry-run.

Credentials come only from the environment (MT_USER, MT_PASS). They are never
read from the configuration file and never written to disk.
"""

import argparse
import json
import os
import ssl
import sys
from datetime import datetime
from pathlib import Path

API_SSL_PORT = 8729

# What the JSON snapshot contains. Read-only paths; a path that the router
# does not have is recorded as an error instead of stopping the snapshot.
SNAPSHOT_PATHS = [
    "/ip/dns",
    "/ip/dns/static",
    "/ip/dhcp-server/network",
    "/ip/dhcp-server/lease",
    "/system/logging",
    "/system/logging/action",
    "/ip/traffic-flow",
    "/ip/traffic-flow/target",
]


class ChangeError(Exception):
    """A change cannot be applied safely. Nothing is modified when it is raised
    during planning."""


# ----------------------------------------------------------------- config ---

def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    if "router" not in config or "host" not in config["router"]:
        raise ChangeError("the configuration needs router.host")
    return config


def connect(router):
    """Opens an API-SSL session. Imported here so the planning code and the
    tests do not need the library."""
    try:
        username = os.environ["MT_USER"]
        password = os.environ["MT_PASS"]
    except KeyError as missing:
        raise ChangeError(f"environment variable {missing.args[0]} is not set") from None

    try:
        import routeros_api
    except ImportError:
        raise ChangeError("the routeros-api package is missing: pip install -r requirements.txt") from None

    verify = router.get("verify_tls", True)
    context = ssl.create_default_context()
    if not verify:
        # For routers that still use the self-signed certificate. The session
        # is encrypted but the router is not authenticated.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return routeros_api.RouterOsApiPool(
        router["host"],
        username=username,
        password=password,
        port=router.get("port", API_SSL_PORT),
        use_ssl=True,
        ssl_context=context,
        ssl_verify=verify,
        ssl_verify_hostname=verify,
        plaintext_login=True,
    )


# -------------------------------------------------------- backup/snapshot ---

def timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def router_backup(api, tag):
    """Asks the router to save a binary backup in its own storage."""
    name = f"{tag}-{timestamp()}"
    api.get_resource("/system/backup").call("save", {"name": name})
    return name + ".backup"


def take_snapshot(api, directory, tag):
    """Saves the relevant configuration as JSON on this computer."""
    data = {}
    for path in SNAPSHOT_PATHS:
        try:
            data[path] = api.get_resource(path).get()
        except Exception as error:  # a missing package must not stop the snapshot
            data[path] = {"error": str(error)}

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{tag}-{timestamp()}.json"
    target.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return target


# ---------------------------------------------------------------- DHCP DNS ---

def plan_dhcp_dns(api, entries, direction):
    """Returns the list of changes needed so every configured DHCP network
    hands out the wanted DNS servers. `direction` is "new" (apply) or "old"
    (rollback). Raises before anything is changed if a network is missing."""
    rows = api.get_resource("/ip/dhcp-server/network").get()
    by_address = {row.get("address"): row for row in rows}

    missing = [entry["network"] for entry in entries if entry["network"] not in by_address]
    if missing:
        raise ChangeError("DHCP network not found on the router: " + ", ".join(missing))

    plan = []
    for entry in entries:
        row = by_address[entry["network"]]
        current = row.get("dns-server", "")
        wanted = entry[direction]
        if current != wanted:
            plan.append({"network": entry["network"], "id": row["id"], "from": current, "to": wanted})
    return plan


def apply_dhcp_dns(api, plan):
    networks = api.get_resource("/ip/dhcp-server/network")
    for change in plan:
        networks.set(id=change["id"], **{"dns-server": change["to"]})


def rollback_note(entries):
    """Text with the manual way back, for the case where this computer is not
    available. It contains commands only, never credentials."""
    lines = ["Manual rollback of the DHCP DNS change (RouterOS terminal):", ""]
    for entry in entries:
        lines.append(
            f'/ip dhcp-server network set [find address="{entry["network"]}"] dns-server={entry["old"]}'
        )
    lines += ["", "Clients take the old servers at their next DHCP renewal."]
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------- monitoring ---

def plan_syslog(api, wanted):
    """Remote logging: one logging action that points to the collector and one
    rule per topic list. Existing matching items are left alone."""
    plan = []
    name = wanted["action_name"]
    params = {
        "name": name,
        "target": "remote",
        "remote": wanted["remote"],
        "remote-port": str(wanted.get("port", 514)),
        "remote-protocol": "udp",
    }
    if wanted.get("src_address"):
        params["src-address"] = wanted["src_address"]

    actions = api.get_resource("/system/logging/action").get()
    existing = next((row for row in actions if row.get("name") == name), None)
    if existing is None:
        plan.append({"path": "/system/logging/action", "op": "add", "params": params})
    else:
        different = {key: value for key, value in params.items() if key != "name" and existing.get(key) != value}
        if different:
            plan.append({"path": "/system/logging/action", "op": "set", "id": existing["id"], "params": different})

    rules = api.get_resource("/system/logging").get()
    for topics in wanted.get("topics", []):
        rule = next((row for row in rules if row.get("action") == name and row.get("topics") == topics), None)
        if rule is None:
            plan.append({"path": "/system/logging", "op": "add", "params": {"topics": topics, "action": name}})
        elif rule.get("disabled") == "true":
            plan.append({"path": "/system/logging", "op": "set", "id": rule["id"], "params": {"disabled": "false"}})
    return plan


def plan_netflow(api, wanted):
    """NetFlow v9 export (RouterOS "traffic flow") to a collector."""
    plan = []
    settings = {
        "enabled": "true",
        "interfaces": wanted["interfaces"],
        "sampling-interval": str(wanted.get("sampling_interval", 100)),
        "packet-sampling": "true",
    }
    rows = api.get_resource("/ip/traffic-flow").get()
    current = rows[0] if rows else {}
    different = {key: value for key, value in settings.items() if current.get(key) != value}
    if different:
        plan.append({"path": "/ip/traffic-flow", "op": "set", "params": different})

    params = {"dst-address": wanted["target"], "port": str(wanted.get("port", 2055)), "version": "9"}
    if wanted.get("src_address"):
        params["src-address"] = wanted["src_address"]

    targets = api.get_resource("/ip/traffic-flow/target").get()
    existing = next(
        (row for row in targets if row.get("dst-address") == params["dst-address"] and row.get("port") == params["port"]),
        None,
    )
    if existing is None:
        plan.append({"path": "/ip/traffic-flow/target", "op": "add", "params": params})
    else:
        different = {key: value for key, value in params.items() if existing.get(key) != value}
        if different:
            plan.append({"path": "/ip/traffic-flow/target", "op": "set", "id": existing["id"], "params": different})
    return plan


def apply_plan(api, plan):
    for step in plan:
        resource = api.get_resource(step["path"])
        if step["op"] == "add":
            resource.add(**step["params"])
        elif "id" in step:
            resource.set(id=step["id"], **step["params"])
        else:
            resource.set(**step["params"])


# -------------------------------------------------------------------- CLI ---

def describe(plan):
    if not plan:
        return ["nothing to change: the router already matches the configuration"]
    lines = []
    for step in plan:
        if "network" in step:
            lines.append(f'{step["network"]}: dns-server "{step["from"]}" -> "{step["to"]}"')
        else:
            target = f' id={step["id"]}' if "id" in step else ""
            lines.append(f'{step["op"]} {step["path"]}{target} {json.dumps(step["params"], sort_keys=True)}')
    return lines


def run_change(api, config, tag, plan, apply, dry_run, out):
    """Common order for every change: show the plan, back up, apply, snapshot."""
    for line in describe(plan):
        out(line)
    if dry_run or not plan:
        return 0

    directory = config.get("snapshot_dir", "snapshots")
    out("router backup: " + router_backup(api, "before-" + tag))
    out("snapshot before: " + str(take_snapshot(api, directory, "before-" + tag)))
    apply(api, plan)
    out("snapshot after: " + str(take_snapshot(api, directory, "after-" + tag)))
    out(f"applied {len(plan)} change(s)")
    return 0


def execute(api, config, args, out=print):
    if args.command == "status":
        out("snapshot: " + str(take_snapshot(api, config.get("snapshot_dir", "snapshots"), "status")))
        return 0

    if args.command == "backup":
        out("router backup: " + router_backup(api, "manual"))
        out("snapshot: " + str(take_snapshot(api, config.get("snapshot_dir", "snapshots"), "manual")))
        return 0

    if args.command == "dns":
        entries = config.get("dhcp_dns", [])
        if not entries:
            raise ChangeError("the configuration has no dhcp_dns entries")
        direction = "new" if args.action == "apply" else "old"
        plan = plan_dhcp_dns(api, entries, direction)
        if args.action == "apply" and plan and not args.dry_run:
            note = Path(config.get("snapshot_dir", "snapshots")) / "ROLLBACK-dhcp-dns.txt"
            note.parent.mkdir(parents=True, exist_ok=True)
            note.write_text(rollback_note(entries), encoding="utf-8")
            out("manual rollback note: " + str(note))
        return run_change(api, config, "dns-" + args.action, plan, apply_dhcp_dns, args.dry_run, out)

    if args.command == "monitoring":
        wanted = config.get("monitoring", {})
        plan = []
        if "syslog" in wanted:
            plan += plan_syslog(api, wanted["syslog"])
        if "netflow" in wanted:
            plan += plan_netflow(api, wanted["netflow"])
        return run_change(api, config, "monitoring", plan, apply_plan, args.dry_run, out)

    raise ChangeError("unknown command")


def build_parser():
    parser = argparse.ArgumentParser(description="Safe configuration changes on a MikroTik router.")
    parser.add_argument("--config", default="config.json", help="path to the configuration file")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status", help="save a JSON snapshot, change nothing")
    commands.add_parser("backup", help="save a router backup and a JSON snapshot")

    dns = commands.add_parser("dns", help="DNS servers handed out by DHCP")
    dns.add_argument("action", choices=["apply", "rollback"])
    dns.add_argument("--dry-run", action="store_true", help="show the changes without applying them")

    monitoring = commands.add_parser("monitoring", help="remote syslog and NetFlow export")
    monitoring.add_argument("action", choices=["apply"])
    monitoring.add_argument("--dry-run", action="store_true", help="show the changes without applying them")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        pool = connect(config["router"])
    except (ChangeError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        api = pool.get_api()  # the connection and the login happen here
    except Exception as error:
        print(f"error: cannot connect to the router: {error}", file=sys.stderr)
        return 1

    try:
        return execute(api, config, args)
    except ChangeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        pool.disconnect()


if __name__ == "__main__":
    sys.exit(main())
