# Quickstart

This repository is the public generator for producing an SSO-enabled service
bundle. It is intended to be used with a site manifest and, when needed, an
external module manifest.

## Prerequisites

- Bash
- Podman
- Node.js 22
- Java 21
- Bazelisk

## Build

Run a build with a site manifest:

```bash
./build.sh --manifest /path/to/manifest.json
```

The generated bundle is written to `dist/`. Build reports, rendered systemd
units, Quadlet output, compatibility runtime models, service contracts, and
helper scripts are written under `dist/build/`.

## Deploy

Copy the generated bundle to the target host, then run:

```bash
cd ~/webservices
./deploy.sh
./verify.sh
```

`deploy.sh` applies the generated systemd user units and Podman bundle runtime.
`verify.sh` waits for readiness and runs blocking stack-contract checks.

## Iterate

For generator source changes, run the local tests first, then rebuild a real
manifest. For private or site-specific service behavior, prefer an external
module and update the site module lock after the module change is pushed.
