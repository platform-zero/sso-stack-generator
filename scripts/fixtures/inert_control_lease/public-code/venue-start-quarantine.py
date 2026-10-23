def host_context(bundle,plan):
    base=Path('/usr/local/libexec')/(plan['prefix']+'-control')
    pointer=base/'agent-services-current-host'
    if not pointer.is_symlink() or pointer.lstat().st_uid!=0:
        raise Refusal('selected installed isolated host role required')
    slot=pointer.resolve(strict=True)
    if slot.parent!=base/'agent-service-releases':raise Refusal('host role escaped selected namespace')
    file=slot/'p0_host_context.py';info=file.lstat()
    if file.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode&0o022 or info.st_nlink!=1:
        raise Refusal('unsafe installed host context code')
    module=load('installed_host_context',file)
    context=module.current(source=file)
    if (context is None or context.namespace!=plan['prefix'] or
            context.data['sourceProvenanceSha256']!=stage.sha(Path(bundle)/'source-provenance.json') or
            context.data['siteVmSpecSha256']!=stage.sha(Path(bundle)/'site/agent-vm.json')):
        raise Refusal('host context does not bind this exact installed bundle/site')
    return context
