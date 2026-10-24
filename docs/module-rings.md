# Module-derived engineering rings

Calibrate a selected delivery in cumulative, dependency-closed module rings.
This does not reduce its full module/service inventory or replace complete
clean-install acceptance. Ring proofs are explicitly scoped engineering proofs.

## Read-only planning

Use the full selected site's manifest and exact module lock plus its complete
fresh generated IR. The policy explicitly assigns **every** selected module to
one ring, including source-only plugins, build roles, initializers and on-demand
runners. Do not infer those from daemon count alone.

```sh
python3 scripts/plan-module-rings.py \
  --manifest /private/site/manifest.json \
  --module-lock /private/site/module-lock.v2.json \
  --ir /private/full-bundle/stack.ir.json \
  --policy /private/site/global.settings/module-rings.json \
  --output /private/new-ring-plan.json
```

The planner checks the full IR's module pins against the full lock, then closes
both module dependencies and actual cross-module service dependencies. Output
records promotions, cumulative services, unchanged full pins and all input
hashes. Unknown/missing/duplicate modules, missing providers, changed pins,
unsupported dependency conditions and forbidden foundation promotions refuse.
It has **no** installation, journal, credential, runtime or activation authority.

## Build and execute

1. Keep the full site manifest/lock and delivery scope authoritative and unchanged.
   Create a separate **private site source snapshot**, not a modified sealed bundle.
2. Select that ring's derived `manifest` from the plan in this source snapshot,
   alongside the same relative site inputs. Commit the private snapshot before
   normal generation. Its components follow explicit module selection rather
   than retaining unrelated application component names.
3. Run the normal generator using its pinned clean module checkouts. Generation
   still validates the selected modules and their real metadata dependencies.
4. Independently qualify the exact selected recipes/COPY inputs and images.
   A prior full-image qualification does not automatically authorize a different
   ring context. Preserve all original source, image, private-directory,
   disjoint-output, reserve and sealed-input checks.
5. Use the **same bundled canonical installer**, source binding, journal, actor
   maps, projection and supported stop paths. Never start arbitrary services
   from a full target or bypass a missing application's ownership input. A ring
   candidate actually selects only the cumulative modules in that ring.
6. Prove startup/readiness, shared identity, denial/revocation, real workflows,
   persistence and clean stop for the ring. Then advance through the supported
   source-bound lifecycle; adding a newly selected stateful module still needs
   owning fresh/existing preparation, not adoption or reset of prior ring data.

A typical foundation selects edge, identity, PostgreSQL, the gateway's actual
Valkey dependency, onboarding and the Keycloak listener **build** module. Actual
service dependencies decide inclusion, not a hardcoded assumption that the
gateway is stateless. Keep MariaDB/Seafile outside that ring if not required;
if a real dependency introduces them, refuse and resolve that boundary rather
than silently omitting a required service.

After cumulative calibration reaches the complete selected inventory, freeze
one final source/module/image/configuration/harness/fault tuple and execute the
required identical full clean installations. Ring passes, image qualification
and native preflight cannot increment their acceptance count. Preserve failed
controls and protected data throughout; never automatically restart a prior
production installation after an engineering failure.
