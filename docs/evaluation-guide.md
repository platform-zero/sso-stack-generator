# Evaluation Guide

Use this guide when evaluating whether a generated stack is ready for release or
deployment.

## Build Evaluation

Run the generator build against a representative manifest. A successful build
must complete TypeScript checks, unit tests, Gradle tests, contract generation,
Bazel packaging, compatibility-contract validation, and systemd/Quadlet rendering.

```bash
./build.sh --manifest /path/to/site/manifest.json
```

Review the generated `dist/build/reports` directory for contract reports and
confirm that selected components match the intended manifest.

## Security Evaluation

Run the generated verifier after deployment:

```bash
cd ~/webservices
./verify.sh
```

The verifier must pass readiness checks and blocking stack-contract tests. Pay
particular attention to unauthenticated access rejection, trusted edge header
handling, OIDC discovery, cookie behavior, service health, and API boundaries.

## Visual Evaluation

For public and optional service modules, screenshots are part of the release
contract. Real screenshots must show the running service with meaningful
authenticated or populated state. Login redirects, blank pages, setup wizards,
and synthetic stand-ins are not acceptable.

## Release Evaluation

Before publishing a generator change, check the same paths CI checks:

```bash
./scripts/test-docs.sh
./scripts/test-env-file-security.sh
./scripts/test-external-modules.sh
./scripts/test-module-runners.sh
./scripts/test-pull-modules.sh
./build.sh --manifest /path/to/site/manifest.json
```
