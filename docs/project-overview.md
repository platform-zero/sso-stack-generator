# Project Overview

The SSO stack generator builds a reproducible self-hosted service bundle around
a shared identity plane, reverse proxy, service modules, and deployment
orchestration. The public generator owns generic stack assembly logic and
runtime models. Site-specific values, encrypted secrets, and private module
choices belong outside this repository.

## Core Responsibilities

- Render Podman bundles, systemd user units, service metadata, and verification
  scripts from a site manifest.
- Provide contract tests for authentication, routing, health, security headers,
  runtime wiring, and generated artifacts.
- Support external stack modules so optional or private services can extend the
  generated bundle without forking the public generator.
- Package a release artifact that can be copied to a target host and deployed
  with the generated `deploy.sh` and `verify.sh` scripts.

## Trust Model

The generated stack assumes the edge proxy terminates public traffic, enforces
the configured routing policy, and passes only trusted identity headers to
services that explicitly opt into forward-auth integration. Services that
support OIDC use Keycloak as the identity provider. Internal service credentials
are emitted from site configuration and should never be committed to this public
repository.

## Extension Model

External modules can contribute runtime overlays, systemd units, stack config,
test-runner routes, seeded data, screenshots, and service contracts. The module
lock records exact revisions so a generated site can be rebuilt and audited
against the same source inputs.
