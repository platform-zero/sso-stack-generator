# Historical fencer function ONLY for AST deadline comparison; never imported.
def _fence(bundle,selector,ledger,reviewed_sha,provenance_sha):
    root_admission()
    require(all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in (reviewed_sha,provenance_sha)))
    bundle,selector,ledger=Path(bundle),Path(selector),Path(ledger)
    protected_tree(bundle);protected_tree(selector.parent)
    selector_raw=protected_file(selector,262144);provenance=protected_file(bundle/'source-provenance.json',262144)
    require(sha(provenance)==provenance_sha)
    operation=HeldOperation();journal=None;parents=[];held={}
    try:
        journal=Journal(ledger);initial,_=journal.check(reviewed_sha);state=strict_json(initial)
        require(encode(state)==initial) # preserve existing canonical history bytes
        plan,context,units,created,closure=actual_context(bundle,selector)
        baseline={k:v for k,v in state.items() if k!=KEY};history=encode(baseline)
        binding={'schemaVersion':1,'namespace':context.namespace,'hostContextSha256':context.digest,
            'provenanceSha256':provenance_sha,'planSha256':sha(canonical(plan)),
            'operationSha256':sha(operation.raw),'sourceClosureSha256':sha(canonical(closure)),
            'ledgerPath':str(ledger),'ledgerParent':journal.parent.identity}
        epoch=reviewed_sha;deadline=time.monotonic()+90
        specs=policy_spec(context)
        for path,mode,body in specs:parents.append(Directory(path.parent))
        with existing_lease(context) as check_lease:
            binding['leaseIdentity']=check_lease.identity
            def check_held():
                for policy in held.values():policy.check()
            def fresh():
                require(time.monotonic()<deadline);root_admission();operation.check();check_lease();check_held()
                journal.check(epoch)
                require(protected_file(selector,262144)==selector_raw
                        and protected_file(bundle/'source-provenance.json',262144)==provenance)
                now=actual_context(bundle,selector)
                require(canonical(now[0])==canonical(plan) and now[1].namespace==context.namespace
                        and now[1].digest==context.digest and now[1].source==context.source
                        and now[1].runtime==context.runtime and canonical(now[2:])==canonical((units,created,closure)))
                require(encode({k:v for k,v in state.items() if k!=KEY})==history)
                native_observations(state,plan,context,units,created,closure)
                for parent in parents:parent.check()
                # Observations may take time: never let changes DURING the private
                # process/job scan evade late source/epoch/held-lease checks.
                operation.check();check_lease()
                latest=actual_context(bundle,selector)
                require(canonical(latest[0])==canonical(plan) and latest[1].digest==context.digest
                        and latest[1].namespace==context.namespace and latest[1].source==context.source
                        and latest[1].runtime==context.runtime and canonical(latest[2:])==canonical((units,created,closure)))
                require(protected_file(selector,262144)==selector_raw
                        and protected_file(bundle/'source-provenance.json',262144)==provenance)
                journal.check(epoch);check_held()
            def commit(phase):
                nonlocal epoch
                fresh();record['phase']=phase
                # Before hashes are an append-only chain of our exact CAS epochs.
                record['intendedEpochs'].append(epoch)
                epoch=journal.write(epoch,state)
            fresh();record=state.get(KEY)
            if record is None:
                policies=[]
                for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                    held[i]=HeldPolicy(parent,path.name,16384,mode)
                    raw,identity=held[i].check();require(raw==body)
                    policies.append({'path':str(path),'mode':mode,'bodySha256':sha(body),'parent':parent.identity,'file':identity})
                record={**binding,'phase':'intended','ledgerSha256Before':reviewed_sha,'policies':policies,'intendedEpochs':[]}
                state[KEY]=record;commit('intended')
            else:
                require(type(record) is dict and set(record)==set(binding)|{'phase','ledgerSha256Before','policies','intendedEpochs'}
                        and all(record[k]==v and type(record[k]) is type(v) for k,v in binding.items())
                        and canonical({k:record[k] for k in binding})==canonical(binding)
                        and record['phase'] in PHASES and type(record['ledgerSha256Before']) is str
                        and re.fullmatch('[0-9a-f]{64}',record['ledgerSha256Before'])
                        and type(record['intendedEpochs']) is list and 1<=len(record['intendedEpochs'])<=6
                        and all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in record['intendedEpochs'])
                        and record['intendedEpochs'][0]==record['ledgerSha256Before']
                        and len(record['intendedEpochs'])==PHASES.index(record['phase'])+1
                        and len(set(record['intendedEpochs']))==len(record['intendedEpochs'])
                        and type(record['policies']) is list and len(record['policies'])==2)
            # Validate the ENTIRE pair before the first deletion or any resumption.
            # Unowned missing/foreign tmpfiles may not be discovered only AFTER sudo.
            for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                saved=record['policies'][i]
                require(type(saved) is dict and set(saved)=={'path','mode','bodySha256','parent','file'}
                        and saved['path']==str(path) and type(saved['mode']) is int and saved['mode']==mode
                        and saved['bodySha256']==sha(body) and type(saved['parent']) is dict
                        and set(saved['parent'])==set(parent.identity)
                        and all(type(x) is int for x in saved['parent'].values()) and saved['parent']==parent.identity)
                identity=saved['file']
                require(type(identity) is dict and set(identity)=={'dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'}
                        and all(type(x) is int for x in identity.values()) and identity['dev']>=0 and identity['ino']>0
                        and identity['uid']==identity['gid']==0 and identity['nlink']==1
                        and identity['mode']==stat.S_IFREG|mode and identity['size']==len(body))
                issued='sudo-issued' if i==0 else 'tmpfiles-issued'
                done='sudo-done' if i==0 else 'tmpfiles-done'
                if record['phase']==issued or PHASES.index(record['phase'])>=PHASES.index(done):
                    require(parent.entry(path.name) is None)
                else:
                    if i not in held:held[i]=HeldPolicy(parent,path.name,16384,mode)
                    require(held[i].check()==(body,identity))
            for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                saved=record['policies'][i]
                require(type(saved) is dict and set(saved)=={'path','mode','bodySha256','parent','file'}
                        and saved['path']==str(path) and type(saved['mode']) is int and saved['mode']==mode
                        and saved['bodySha256']==sha(body) and saved['parent']==parent.identity)
                identity=saved['file']
                require(type(identity) is dict and set(identity)=={'dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'}
                        and all(type(x) is int for x in identity.values()) and identity['dev']>=0 and identity['ino']>0
                        and identity['uid']==identity['gid']==0 and identity['nlink']==1
                        and identity['mode']==stat.S_IFREG|mode and identity['size']==len(body))
                issued='sudo-issued' if i==0 else 'tmpfiles-issued';done='sudo-done' if i==0 else 'tmpfiles-done'
                current=PHASES.index(record['phase'])
                if current>=PHASES.index(done):require(parent.entry(path.name) is None);continue
                if record['phase']==issued:
                    require(parent.entry(path.name) is None) # PRESENT even original => no second delete
                    fresh();os.fsync(parent.fd);commit(done);continue
                require(record['phase']==('intended' if i==0 else 'sudo-done'))
                require(held[i].check()==(body,identity))
                commit(issued)
                # Issued durability precedes ALL destructive calls. Recheck late.
                fresh();require(held[i].check()==(body,identity))
                if i:require(parents[0].entry(specs[0][0].name) is None)
                parent.check();check_held();os.unlink(path.name,dir_fd=parent.fd)
                held[i].own_unlinked();os.fsync(parent.fd);check_held()
                require(parent.entry(path.name) is None);commit(done)
            fresh();require(all(parent.entry(path.name) is None for (path,_,_),parent in zip(specs,parents)))
            if record['phase']!='fenced':commit('fenced')
            fresh();require(all(parent.entry(path.name) is None for (path,_,_),parent in zip(specs,parents)))
            return {'status':'fenced-two-generated-host-policies','policiesAbsent':2,'servicesStarted':False,
                    'nativeRecoveryAuthorized':False,'acceptedIntegratedInstalls':0}
    finally:
        # Attempt every close, including when an earlier cleanup itself fails.
        with ExitStack() as closing:
            closing.callback(operation.close)
            if journal is not None:closing.callback(journal.close)
            for parent in parents:closing.callback(parent.close)
            for policy in held.values():closing.callback(policy.close)
