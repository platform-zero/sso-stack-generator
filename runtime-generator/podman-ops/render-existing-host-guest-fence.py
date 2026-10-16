#!/usr/bin/env python3
"""Render a proposed, narrow nftables guest isolation fence. Never apply it.

Acceptance requires atomic installation *before* activating the guest network,
followed by namespace/interface/listener tests and exact scoped teardown.
"""
import argparse
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('private_ingress',Path(__file__).with_name('render-existing-host-ingress.py'))
ingress=importlib.util.module_from_spec(spec);spec.loader.exec_module(ingress)
mail_spec=importlib.util.spec_from_file_location('private_mail_ingress',Path(__file__).with_name('render-existing-host-mail-ingress.py'))
mail=importlib.util.module_from_spec(mail_spec);mail_spec.loader.exec_module(mail)


def render(bundle,selector):
    proposal=ingress.render(bundle,selector)
    mail_proposal=mail.render(bundle,selector)
    gateway=proposal['guestGateway']; bridge=proposal['bridge']; mapped=proposal['guestPorts'][1]
    if mail_proposal['guestGateway']!=gateway or mail_proposal['bridge']!=bridge:
        raise ingress.Refusal('Mail transport and Caddy guest interface differ')
    smtp=selector['ports']['587']; imap=selector['ports']['993']
    ports=selector['ports'];prefix=selector['unitPrefix'];http=proposal['guestHttpPorts'][1]
    for old in ('7880','7881','7882'):
        if type(ports.get(old)) is not int or ports[old] not in range(1024,65536):
            raise ingress.Refusal('Unbound Livekit transport port')
    livekit=Path(bundle)/'quadlet/rootless-apps'/f'{prefix}-livekit.container'
    if not livekit.is_file() or livekit.is_symlink():
        raise ingress.Refusal('Missing private rootless Livekit Quadlet')
    lines=livekit.read_text().splitlines()
    expected={f'PublishPort=127.0.0.1:{ports["7880"]}:7880',
              f'PublishPort={gateway}:{ports["7881"]}:{ports["7881"]}/tcp',
              f'PublishPort={gateway}:{ports["7882"]}:{ports["7882"]}/udp'}
    if ('Network=host' in lines or {v for v in lines if v.startswith('PublishPort=')}!=expected
            or len([v for v in lines if v.startswith('PublishPort=')])!=3
            or f'ContainerName={prefix}-livekit' not in lines):
        raise ingress.Refusal('Livekit API/ICE publisher escapes Caddy and guest-only RTC scope')
    allowed=f'22, 53, 80, 443, 587, 993, {http}, {mapped}, {smtp}, {imap}, {ports["7881"]}'
    protected=f'53, 80, 443, 587, 993, {http}, {mapped}, {smtp}, {imap}, {ports["7881"]}'
    table=proposal['unit'].replace('-ingress-https','').replace('-','_')+'_guest_fence'
    # An accept in this table never bypasses any other host security table.
    # The default ACCEPT policy applies to unrelated pre-existing host work.
    text=f'''table inet {table} {{
  chain guest_host_input {{
    type filter hook input priority -50; policy accept;
    iifname "{bridge}" meta nfproto ipv6 drop
    iifname "{bridge}" ip daddr != {gateway} drop
    iifname "{bridge}" meta l4proto != {{ tcp, udp, icmp }} drop
    iifname "{bridge}" ip daddr {gateway} tcp dport != {{ {allowed} }} drop
    iifname "{bridge}" ip daddr {gateway} udp dport != {{ 53, 67, {ports["7882"]} }} drop
    iifname != "{bridge}" iifname != "lo" ip daddr {gateway} tcp dport {{ {protected} }} drop
    iifname != "{bridge}" iifname != "lo" ip daddr {gateway} udp dport {{ 53, {ports["7882"]} }} drop
  }}
  chain guest_forward {{
    type filter hook forward priority -50; policy accept;
    iifname "{bridge}" meta nfproto ipv6 drop
    iifname "{bridge}" ip daddr 10.0.0.0/8 drop
    iifname "{bridge}" ip daddr 172.16.0.0/12 drop
    iifname "{bridge}" ip daddr 192.168.0.0/16 drop
  }}
}}
'''
    return {'schemaVersion':1,'table':table,'nftables':text,
            'bridge':bridge,'gateway':gateway,'caddyPorts':[80,http,443,mapped],
            'mailPorts':[587,smtp,993,imap],
            'livekitRtcPorts':{'tcp':ports['7881'],'udp':ports['7882']},
            'applied':False,'activationAuthorized':False,
            'otherHostTablesModified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--selector',type=Path,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(render(args.bundle,ingress.network.strict_json(args.selector)),sort_keys=True,indent=2))
    except (ingress.Refusal,ingress.network.Refusal,mail.ingress.Refusal,mail.ingress.network.Refusal,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('private guest fence refused: '+str(exc)) from exc


if __name__=='__main__':main()
