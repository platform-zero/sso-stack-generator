#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
source "$ROOT_DIR/scripts/lib/render-values.sh"
original="$ROOT_DIR/../site-config-first-install/sites/latium/global.settings/stack.config.yaml"
[ -f "$original" ] || exit 1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 - "$original" "$work/venue.yaml" <<'PY'
from pathlib import Path
import sys
source=Path(sys.argv[1]).read_text()
assert source.count('\npodman:\n')==1
source=source.replace('\npodman:\n', '\npodman:\n  unit_prefix: p0test-r1\n  port_map:\n    "443": 56042\n    "80": 56045\n',1)
Path(sys.argv[2]).write_text(source)
base=Path(sys.argv[1]).read_text()
normal=base.replace('\npodman:\n', '\npodman:\n  unit_prefix: webservices\n',1)
Path(sys.argv[2]).with_name('normal.yaml').write_text(normal)
Path(sys.argv[2]).with_name('mixed.yaml').write_text(normal.replace('  unit_prefix: webservices\n', '  unit_prefix: webservices\n  port_map:\n    "443": 56042\n    "80": 56045\n',1))
Path(sys.argv[2]).with_name('unknown.yaml').write_text(normal.replace('unit_prefix: webservices', 'unit_prefix: unreviewed'))
PY
load_site_values "$original"
legacy=$(build_caddy_global_options deploy "$(render_get CADDY_TLS_MODE)")
[[ $legacy == *$'\tlocal_certs'* && $legacy != *default_bind* && $legacy != *https_port* && $legacy != *'admin off'* ]] || exit 1
load_site_values "$work/normal.yaml"
normal=$(build_caddy_global_options deploy "$(render_get CADDY_TLS_MODE)")
[[ $normal == "$legacy" ]] || { echo 'explicit normal native profile changed Caddy listeners' >&2; exit 1; }
log_regex=$(render_get STACK_LOG_UNIT_REGEX)
[[ 'webservices-caddy.service;' =~ $log_regex && 'user@42.service;webservices-forgejo.service' =~ $log_regex ]] || exit 1
[[ ! 'unrelated.service;' =~ $log_regex && ! 'user@43.service;worklane-example.service' =~ $log_regex ]] || exit 1
for rejected in mixed unknown; do
  if (load_site_values "$work/$rejected.yaml" >/dev/null 2>&1); then
    echo "unreviewed mixed/native Caddy profile accepted: $rejected" >&2; exit 1
  fi
done
load_site_values "$work/venue.yaml"
private=$(build_caddy_global_options deploy "$(render_get CADDY_TLS_MODE)")
[[ $private == *$'\tadmin off'* && $private == *$'\tdefault_bind 127.0.0.1'* && $private == *$'\thttp_port 56045'* &&
   $private == *$'\thttps_port 56042'* && $private == *$'\tauto_https disable_redirects'* &&
   $private == *$'\tservers {\n\t\tprotocols h1 h2\n\t}'* &&
   $private != *'0.0.0.0'* ]] || exit 1
log_regex=$(render_get STACK_LOG_UNIT_REGEX)
[[ 'p0test-r1-caddy.service;' =~ $log_regex && ! 'webservices-caddy.service;' =~ $log_regex ]] || exit 1
for bad in '443:56045:local' '56042:80:local' '56042:56042:local' '56042:56045:acme' '56042:56045:bogus'; do
  IFS=: read -r https http tls <<< "$bad"
  if (render_set CADDY_VENUE_HTTPS_PORT "$https"; render_set CADDY_VENUE_HTTP_PORT "$http";
      build_caddy_global_options deploy "$tls" >/dev/null 2>&1); then
    echo "unsafe Caddy venue tuple accepted: $bad" >&2; exit 1
  fi
done
if (render_set CADDY_VENUE_HTTPS_PORT 56042; render_set CADDY_VENUE_HTTP_PORT 56045;
    sops() { printf '%s\n' '{"CADDY_VENUE_HTTPS_PORT":"443"}'; }
    printf '%s\n' 'fixture' > "$work/sealed.json"
    load_secret_store "$work/sealed.json" >/dev/null 2>&1); then
  echo 'sealed site listener override was accepted' >&2; exit 1
fi
load_site_values "$original"
[[ -z $(render_get CADDY_VENUE_HTTPS_PORT) && -z $(render_get CADDY_VENUE_HTTP_PORT) ]] || exit 1
printf '%s\n' '[caddy-private-ingress-source] default site unchanged; loopback high-port venue bounded; hostile inputs refused'
