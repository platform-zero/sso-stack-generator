#!/usr/bin/env python3
"""Read-only map of ACTUAL Quadlet persistent sources versus site volume labels.

Selector labels alone are not installation/reset authority: rootless generated
Quadlets rewrite many source paths into domain-owned volume roots. This tool
never creates a volume, sets an ACL or authorizes activation.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import os

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_owned_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal
NAMED={'huly_cockroach','huly_elastic','huly_minio','huly_redpanda'}

def inspect(bundle,selector):
    bundle=Path(bundle);authority=json.loads(Path(selector).read_text())
    plan=stage.owned_plan(bundle,selector)
    volumes=authority['volumes']
    if len(volumes)!=59 or not NAMED<=set(volumes):raise Refusal('59 selected volume labels differ')
    domains={a['name'].removeprefix(plan['prefix']+'-'):a for a in plan['accounts']}
    references={};nested_ca=set()
    for directory in sorted((bundle/'quadlet').iterdir()):
        domain=directory.name
        if domain!='rootful' and (not domain.startswith('rootless-') or domain.removeprefix('rootless-') not in domains):
            raise Refusal('unknown Quadlet domain')
        for unit in sorted(directory.glob('*.container')):
            if unit.is_symlink():raise Refusal('linked Quadlet in volume inventory')
            for line in unit.read_text().splitlines():
                if not line.startswith('Volume='):continue
                source=line[7:].split(':',1)[0]
                if source in NAMED:
                    if domain!='rootless-apps':raise Refusal('Huly named volume escaped apps graph')
                    kind='named-huly'
                elif source.startswith('%t/'):
                    if source!='%t/podman/podman.sock':raise Refusal('unknown rootless runtime socket')
                    continue
                elif not source.startswith('/') or '..' in Path(source).parts or os.path.normpath(source)!=source:
                    raise Refusal('noncanonical Quadlet bind source')
                else:
                    roots=[('rootful',authority['rootful']['volumeRoot'])]
                    roots.extend(('rootless-'+name,a['volume']) for name,a in sorted(domains.items()))
                    matching=[name for name,root in roots if source.startswith(root.rstrip('/')+'/')]
                    if matching:
                        if len(matching)!=1:raise Refusal('ambiguous selected volume source')
                        root=Path(dict(roots)[matching[0]])
                        if Path(source).parent!=root:
                            if (source!=str(root/'caddy_ca/caddy-ca.crt') or
                                    domain!='rootless-test-runners'):
                                raise Refusal('unclassified nested selected volume source')
                            nested_ca.add((source,domain))
                            continue
                        kind='data-bind-'+matching[0]
                    else:
                        # Non-data release/config, SSD, fixtures, control and
                        # protected external binds belong to separate gates.
                        continue
                key=source if kind=='named-huly' else Path(source).name
                if key not in volumes:raise Refusal('data bind omitted from selected volume labels: '+key)
                references.setdefault(key,{}).setdefault(source,set()).add(domain)
    if set(references)&NAMED!=NAMED:raise Refusal('four Huly named sources absent')
    bind_sources={source for name,sources in references.items() for source in sources if name not in NAMED}
    if len(bind_sources)!=54:
        raise Refusal('expected 54 unique data bind sources, got '+str(len(bind_sources)))
    # Cross-domain data is deliberately recorded as one source and multiple
    # consumers; never grant an ACL or assume a selector label is the path.
    mismatched={name:sorted(sources) for name,sources in references.items()
                if name not in NAMED and sorted(sources)!=[volumes[name]]}
    return {'schemaVersion':1,'scope':'read-only generated Quadlet data-source classification',
            'selectedVolumeLabels':len(volumes),'actualDataBindSources':len(bind_sources),
            'selectedNamedVolumes':sorted(NAMED),'pathDivergences':mismatched,
            'nestedCaFileConsumers':[{'source':source,'consumer':consumer} for source,consumer in sorted(nested_ca)],
            'unreferencedSelectorLabels':sorted(set(volumes)-set(references)),
            'dataSources':{name:{source:sorted(consumers) for source,consumers in sorted(paths.items())}
                           for name,paths in sorted(references.items())},
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',required=True);p.add_argument('--selector',required=True)
    args=p.parse_args()
    try:print(json.dumps(inspect(args.bundle,args.selector),sort_keys=True))
    except (Refusal,KeyError,TypeError,ValueError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('venue data-source classification refused: '+str(exc)) from exc
if __name__=='__main__':main()
