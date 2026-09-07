#!/usr/bin/env python3
"""Client for the Platform Zero root host broker."""

import argparse
import json
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["stage", "preflight", "snapshot", "activate", "status", "verify", "logs", "restore", "finalize-access"])
    parser.add_argument("--bundle")
    parser.add_argument("--release")
    parser.add_argument("--sha256")
    parser.add_argument("--domain", default="rootful")
    parser.add_argument("--unit")
    parser.add_argument("--snapshot")
    parser.add_argument("--confirm")
    parser.add_argument("--socket", default="/run/platform-zero/host-broker.sock")
    args = parser.parse_args()
    request = {key: value for key, value in vars(args).items() if key != "socket" and value is not None}
    request["version"] = 1
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(args.socket)
        client.sendall(json.dumps(request).encode() + b"\n")
        response = b""
        while b"\n" not in response:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    if not response:
        print("p0-hostctl: host broker closed the connection without a response", file=sys.stderr)
        return 1
    try:
        decoded = json.loads(response)
    except json.JSONDecodeError as error:
        print(f"p0-hostctl: invalid host broker response: {error}", file=sys.stderr)
        return 1
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0 if decoded.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
