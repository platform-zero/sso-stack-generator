#!/usr/bin/env python3
"""Client for the Platform Zero root host broker."""

import argparse
import json
import socket
import sys


def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid broker response")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["status", "diagnostics", "verify", "logs", "operation-status", "plan", "apply", "test"])
    parser.add_argument("--bundle")
    parser.add_argument("--release")
    parser.add_argument("--sha256")
    parser.add_argument("--operation-id")
    parser.add_argument("--plan-id")
    parser.add_argument("--suite")
    parser.add_argument("--domain", default="rootful")
    parser.add_argument("--unit")
    parser.add_argument("--socket", default="/run/platform-zero/host-broker.sock")
    args = parser.parse_args()
    request = {key: value for key, value in vars(args).items() if key != "socket" and value is not None}
    request["version"] = 1
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(args.socket)
        client.sendall(json.dumps(request).encode() + b"\n")
        response = b""
        client.settimeout(120)
        while b"\n" not in response and len(response) <= 1024 * 1024:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    if not response:
        print("p0-hostctl: host broker closed the connection without a response", file=sys.stderr)
        return 1
    try:
        if len(response) > 1024 * 1024 or not response.endswith(b"\n"):
            raise ValueError("invalid broker response")
        decoded = json.loads(response, object_pairs_hook=unique_json_pairs)
        if not isinstance(decoded, dict) or type(decoded.get("ok")) is not bool:
            raise ValueError("invalid broker response")
    except (ValueError, UnicodeError):
        print("p0-hostctl: invalid host broker response", file=sys.stderr)
        return 1
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0 if decoded.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
