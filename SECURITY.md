# Security Policy

This repository contains platform code for authenticated web services, identity, routing, secret rendering, and service bootstrap flows.

## Reporting Security Issues

Do not open public issues containing:

- real secrets
- private keys
- access tokens
- production hostnames that are not already public
- screenshots exposing private user data
- exploit steps against a live deployment

For a private report, use GitHub private vulnerability reporting if it is
enabled for the repository. If it is not enabled, contact the repository owner
privately before sharing sensitive details.

## Scope

This project includes generator source, documentation, templates, and test
tooling.

Site-specific secrets, private client deployments, and production runtime
values live outside this repository.

## Supported Branches

The current public support target is `dev`, which is also the active
development branch in this checkout. A separate `stable` branch may improve
buyer trust once release-quality docs and validation are established, but this
repository does not require that branch to exist yet.

## Secrets Handling

This project is designed so that:

- local builds do not decrypt secrets
- deploy-time secret rendering happens on the target host
- rendered runtime material stays outside source control
- site-specific secret stores live outside this repository

If you find plaintext credentials committed to the repository, treat that as a security bug.

## Deployment Safety

The stack is intended for operators who understand Podman, systemd user services, SOPS, and reverse proxy routing. Review site-specific configuration before exposing a deployment to the public internet.

## Security Model

The platform expects:

- centralized identity
- explicit service routes
- SOPS-backed secrets
- target-host secret rendering
- verification after deploy
- documented service standards
