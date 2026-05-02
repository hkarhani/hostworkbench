#!/usr/bin/env python3
"""Interactive public API demo client for Host Workbench."""

import argparse
import ipaddress
import json
import os
import random
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


HOST_COLUMNS = ["hostIP", "registered", "groups"]
HIDDEN_COLUMNS = {"id", "_id", "createdAt", "updatedAt", "fieldChanges", "changeLog"}


class ApiClient:
    def __init__(self, base_url: str, api_key: str, verify_tls: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.token = ""
        self.context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request_headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)

        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, context=self.context, timeout=20) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} failed: HTTP {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{method} {path} failed: {exc.reason}") from exc

    def authenticate(self) -> None:
        data = self.request(
            "/public/auth/token",
            method="POST",
            headers={"X-API-Key": self.api_key},
        )
        self.token = data["access_token"]
        print(f"Authenticated. JWT expires in {data['expires_in']} seconds.")

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def list_hosts(self) -> list[dict[str, Any]]:
        return self.request("/public/hosts", headers=self.auth_headers())

    def create_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("/public/hosts", method="POST", data=payload, headers=self.auth_headers())

    def update_host(self, host_ip: str, payload: dict[str, Any]) -> dict[str, Any]:
        safe_ip = urllib.parse.quote(host_ip, safe="")
        return self.request(
            f"/public/hosts/{safe_ip}",
            method="PUT",
            data=payload,
            headers=self.auth_headers(),
        )

    def add_host_to_group(self, host_ip: str, group_name: str) -> dict[str, Any]:
        safe_ip = urllib.parse.quote(host_ip, safe="")
        safe_group = urllib.parse.quote(group_name, safe="")
        return self.request(
            f"/public/hosts/{safe_ip}/groups/{safe_group}",
            method="PUT",
            headers=self.auth_headers(),
        )

    def remove_host_from_group(self, host_ip: str, group_name: str) -> dict[str, Any]:
        safe_ip = urllib.parse.quote(host_ip, safe="")
        safe_group = urllib.parse.quote(group_name, safe="")
        return self.request(
            f"/public/hosts/{safe_ip}/groups/{safe_group}",
            method="DELETE",
            headers=self.auth_headers(),
        )

    def list_groups(self) -> list[dict[str, Any]]:
        return self.request("/public/groups", headers=self.auth_headers())


def pause(message: str) -> None:
    input(f"\n{message}\nPress Enter to continue...")


def compact(value: Any, max_len: int = 42) -> str:
    if isinstance(value, bool):
        text = "True" if value else "False"
    elif value is None:
        text = ""
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
    else:
        text = str(value)

    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def print_hosts(hosts: list[dict[str, Any]], title: str) -> None:
    print(f"\n=== {title} ===")
    if not hosts:
        print("No hosts returned.")
        return

    columns = HOST_COLUMNS
    rows = [[compact(host.get(column)) for column in columns] for host in hosts]
    widths = [
        min(44, max(len(column), *(len(row[index]) for row in rows)))
        for index, column in enumerate(columns)
    ]

    header = " | ".join(column.ljust(widths[index]) for index, column in enumerate(columns))
    divider = "-+-".join("-" * width for width in widths)
    print(header)
    print(divider)
    for row in rows:
        print(" | ".join(row[index].ljust(widths[index]) for index in range(len(columns))))


def print_groups(groups: list[dict[str, Any]], title: str) -> None:
    print(f"\n=== {title} ===")
    if not groups:
        print("No groups returned.")
        return
    for group in groups:
        members = ", ".join(group.get("members", [])) or "no members"
        print(f"{group['name']}: {members}")


def print_host_detail(host: dict[str, Any], title: str) -> None:
    print(f"\n=== {title}: {host.get('hostIP')} ===")
    for key in sorted(key for key in host if key not in HIDDEN_COLUMNS):
        print(f"{key}: {compact(host[key], max_len=90)}")

    changes = host.get("fieldChanges") or {}
    if changes:
        print("registration changes shown in GUI:")
        for field, meta in sorted(changes.items()):
            when = meta.get("changedAt", "unknown time") if isinstance(meta, dict) else "unknown time"
            source = meta.get("source", "unknown source") if isinstance(meta, dict) else "unknown source"
            print(f"  - {field}: {when} via {source}")


def choose_new_ip(subnet: str, existing_hosts: list[dict[str, Any]]) -> str:
    network = ipaddress.ip_network(subnet, strict=False)
    existing = {host.get("hostIP") for host in existing_hosts}
    candidates = [str(ip) for ip in network.hosts() if str(ip) not in existing]
    if not candidates:
        raise RuntimeError(f"No free host IPs remain in {network}")
    return random.choice(candidates)


def build_new_host(host_ip: str) -> dict[str, Any]:
    return {
        "hostIP": host_ip,
        "registered": random.choice([True, False]),
        "groups": ["dev"],
    }


def build_update_payload(host: dict[str, Any]) -> dict[str, Any]:
    return {
        "registered": not bool(host.get("registered", False)),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive client for testing the Host Workbench public API.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("FSDEMO_BASE_URL", "https://localhost:8443"),
        help="Remote app base URL. Default: https://localhost:8443",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("FSDEMO_API_KEY"),
        help="Demo API key. You can also set FSDEMO_API_KEY.",
    )
    parser.add_argument(
        "--subnet",
        default="192.0.2.0/24",
        help="Subnet used to choose a free IP for the new test host.",
    )
    parser.add_argument(
        "--updates",
        type=int,
        default=3,
        help="Number of Enter-driven registration flips to perform.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificate. Leave disabled for the demo self-signed certificate.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print("Missing API key. Pass --api-key or set FSDEMO_API_KEY.", file=sys.stderr)
        return 2
    if args.updates < 1:
        print("--updates must be at least 1.", file=sys.stderr)
        return 2

    client = ApiClient(args.base_url, args.api_key, verify_tls=args.verify_tls)
    print(f"Target app: {args.base_url}")
    client.authenticate()

    pause("Step 1: list current hosts, registration states, and groups in the public API.")
    hosts = client.list_hosts()
    print_hosts(hosts, "Current public hosts")
    print_groups(client.list_groups(), "Current public groups")

    pause("Step 2: create one new host through POST /public/hosts.")
    new_ip = choose_new_ip(args.subnet, hosts)
    new_host_payload = build_new_host(new_ip)
    print("Posting host payload:")
    print(json.dumps(new_host_payload, indent=2, sort_keys=True))
    created = client.create_host(new_host_payload)
    print_host_detail(created, "Created host")

    pause("Step 3: add the new host to the critical group through PUT /public/hosts/{ip}/groups/critical.")
    created = client.add_host_to_group(created["hostIP"], "critical")
    print_host_detail(created, "Host after group add")
    print_groups(client.list_groups(), "Groups after add")

    pause("Step 4: remove the new host from the dev group through DELETE /public/hosts/{ip}/groups/dev.")
    created = client.remove_host_from_group(created["hostIP"], "dev")
    print_host_detail(created, "Host after group remove")
    print_groups(client.list_groups(), "Groups after remove")

    pause("Refresh the full list after the group changes appear in the GUI.")
    hosts = client.list_hosts()
    print_hosts(hosts, "Hosts after create and group changes")

    candidates = hosts[:]
    print(f"\nStep 5: perform {args.updates} Enter-driven registration flips.")
    if len(candidates) >= args.updates:
        update_targets = random.sample(candidates, args.updates)
    else:
        update_targets = [random.choice(candidates) for _ in range(args.updates)]

    for step, target in enumerate(update_targets, start=1):
        host = next((item for item in candidates if item["hostIP"] == target["hostIP"]), target)

        payload = build_update_payload(host)
        pause(f"Update {step}: flip registered for {host['hostIP']}.")
        print("PUT payload:")
        print(json.dumps(payload, indent=2, sort_keys=True))
        updated = client.update_host(host["hostIP"], payload)
        print_host_detail(updated, f"Updated host {step}")

        hosts = client.list_hosts()
        candidates = hosts[:]
        print_hosts(hosts, f"Hosts after update {step}")

    print("\nDone. Keep the web UI open to see highlighted registration changes and timestamps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
