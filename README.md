# MikroTik change tools

A small Python tool for making configuration changes on a MikroTik router through the RouterOS API, in a way that can always be undone.

It grew out of two changes I had to make on a production office router without breaking the network for the people working on it:

- moving every DHCP network to a new DNS resolver (a filtering resolver, with the router as second server)
- turning on remote logging to a SIEM and NetFlow export to a traffic collector

Doing this by hand in WinBox works once. Doing it safely, and being able to go back in one command, is what the tool is for.

## How a change runs

Every command that modifies the router follows the same order:

1. **Plan.** Read the current state and work out the differences. If something is wrong (for example a DHCP network from the configuration does not exist on the router) it stops here, before anything is modified.
2. **Back up.** Ask the router to save a binary backup in its own storage.
3. **Snapshot.** Save the relevant configuration as JSON on this computer.
4. **Apply** only the differences.
5. **Snapshot again**, so before and after can be compared.

Running the same command twice changes nothing the second time, and takes no backup. `--dry-run` shows the plan and stops after step 1.

## Commands

```text
python mtchange.py status                      save a JSON snapshot, change nothing
python mtchange.py backup                      router backup + JSON snapshot
python mtchange.py dns apply [--dry-run]       DHCP networks hand out the new DNS servers
python mtchange.py dns rollback [--dry-run]    put the old DNS servers back
python mtchange.py monitoring apply [--dry-run] remote syslog + NetFlow v9 export
```

`dns apply` also writes `ROLLBACK-dhcp-dns.txt` with the RouterOS commands that undo the change by hand, for the case where this computer is not available.

Example:

```text
> python mtchange.py dns apply --dry-run
10.0.10.0/24: dns-server "10.0.10.1,1.1.1.1" -> "10.0.10.53,10.0.10.1"
10.0.20.0/24: dns-server "10.0.20.1" -> "10.0.10.53,10.0.20.1"
```

## Setup

```bat
pip install -r requirements.txt
copy config.example.json config.json
set MT_USER=api-user
set MT_PASS=...
python mtchange.py status
```

The router needs the `api-ssl` service enabled (port 8729) and a user that is allowed to use the API. Restrict that service to the management network.

### Configuration

`config.json` describes the wanted state. The addresses in `config.example.json` are placeholders.

| Key | Meaning |
|---|---|
| `router.host`, `router.port` | where the API listens |
| `router.verify_tls` | `true` checks the router's certificate. `false` is for routers that still use the self-signed one: the session is encrypted, but the router is not authenticated |
| `snapshot_dir` | where snapshots and the rollback note are written |
| `dhcp_dns[]` | per DHCP network: the `new` DNS servers and the `old` ones to return to |
| `monitoring.syslog` | name of the logging action, collector address and port, topic lists |
| `monitoring.netflow` | collector address and port, interfaces, sampling interval |

### Credentials

The user name and password are read only from the environment variables `MT_USER` and `MT_PASS`. They are not accepted in the configuration file and are never written to snapshots or to the rollback note. `config.json` and `snapshots/` are in `.gitignore`.

## Tests

```bat
python -m unittest discover -s tests -v
```

The tests run against an in-memory stand-in for the RouterOS API, so they need no router. They check that:

- only the configured networks are changed, and rollback restores the old values
- a missing network stops the command before any change
- the backup is taken before the first change, and not at all when there is nothing to do
- `--dry-run` changes nothing and writes no files
- the monitoring setup is idempotent and repairs only the field that differs
- credentials never appear in the files the tool writes

The connection layer was checked against `routeros-api` 0.21. The original, site-specific version of these changes was used on RouterOS 7.

## Limits

- It covers the two changes described above, not general router management.
- The binary backup stays on the router. Download it if the router itself is at risk.
- Snapshots contain DHCP leases (device names and MAC addresses). Treat the snapshot folder as internal data.
