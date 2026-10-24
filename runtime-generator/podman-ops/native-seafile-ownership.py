#!/usr/bin/env python3
"""Main's Seafile protocol checks. No CLI, permit emitter or adoption API.

Pure byte/proof checks below confer no authority. Binding requires the canonical
preparing dual records, FD9, original source/marker/current custody and native
offline checks; execution/publication belongs to the journal transaction.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

HEX = re.compile(r'[a-f0-9]{64}')
FIELDS = {'version', 'module', 'scope_id', 'receipt_sha256', 'operation',
          'state_kind', 'shared_identity', 'contact_email', 'local_user',
          'expected_account_sha256', 'marker_sha256', 'implementation_sha256',
          'password_sha256', 'fresh_nonce', 'database_scope'}
MARKER_FIELDS = ('version', 'module', 'scope_id', 'receipt_sha256', 'fresh_nonce',
                 'shared_identity', 'database_scope')
PROOF_FIELDS = {'version', 'module', 'operation', 'scope_id', 'receipt_sha256',
                'fresh_nonce', 'marker_sha256', 'implementation_sha256',
                'shared_identity', 'local_user', 'account_sha256'}
IMPLEMENTATION_FILES = ('seafile/runtime-entrypoint.sh', 'seafile/admin_ownership.py',
                        'seafile/remote_user.py', 'seafile/native_start.py',
                        'seafile/seahub_settings.py')
IMPLEMENTATION_TARGETS = ('/runtime-entrypoint.sh', '/seafile_admin_ownership.py',
                          '/seafile_remote_user.py', '/seafile_native_start.py',
                          '/seahub_settings_overlay.py')
AUTH_SOURCE = 'seafile-admin/authorization.json'
PROOF_PREFIX = b'WEBSERVICES_SEAFILE_ADMIN_PROOF='


class Refused(ValueError):
    pass


def require(value, message='Seafile canonical ownership contract refused'):
    if not value:
        raise Refused(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate Seafile ownership key')
        value[key] = item
    return value


def strict(body):
    require(isinstance(body, bytes) and len(body) <= 65536)
    return json.loads(body, object_pairs_hook=unique)


def validate_authorization(raw, expected_hash, operation, marker, implementation):
    """Main-owned pure schema check; NEVER import service code as Host Root.

    The owning module independently checks these same bytes in its mapped native
    namespace. Cross-source tests enforce parity; neither check mints authority.
    """
    require(isinstance(expected_hash, str) and HEX.fullmatch(expected_hash) and sha(raw) == expected_hash)
    auth = strict(raw)
    require(isinstance(auth, dict) and set(auth) == FIELDS)
    require(type(auth['version']) is int and auth['version'] == 1 and auth['module'] == 'seafile')
    require(operation in ('create-fresh', 'verify-existing') and auth['operation'] == operation)
    require(isinstance(auth['scope_id'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', auth['scope_id']))
    for key in ('receipt_sha256', 'marker_sha256', 'implementation_sha256', 'fresh_nonce'):
        require(isinstance(auth[key], str) and HEX.fullmatch(auth[key]))
    require(sha(marker) == auth['marker_sha256'] and sha(implementation) == auth['implementation_sha256'])
    require(strict(marker) == {key: auth[key] for key in MARKER_FIELDS})
    database = auth['database_scope']
    require(isinstance(database, dict) and set(database) == {'host', 'port', 'user', 'schemas'})
    require(isinstance(database['host'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', database['host']))
    require(type(database['port']) is int and 1 <= database['port'] <= 65535)
    require(isinstance(database['user'], str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', database['user']))
    require(isinstance(database['schemas'], list) and len(database['schemas']) == 3
            and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) for name in database['schemas'])
            and len(set(database['schemas'])) == 3)
    identity = auth['shared_identity']
    require(isinstance(identity, dict) and set(identity) == {'issuer', 'subject', 'remote_user'})
    require(all(isinstance(value, str) and 0 < len(value) <= 2048 and value == value.strip()
                and not any(ord(char) < 32 or ord(char) == 127 for char in value) for value in identity.values()))
    issuer = urlsplit(identity['issuer'])
    require(issuer.scheme == 'https' and issuer.hostname and not issuer.username and not issuer.password
            and not issuer.query and not issuer.fragment and identity['remote_user'] == identity['subject'])
    email = auth['contact_email']
    require(isinstance(email, str) and len(email) <= 225 and email == email.strip().lower()
            and not any(ord(char) < 32 or ord(char) == 127 for char in email)
            and re.fullmatch(r'[^\s@]+@[^\s@]+', email))
    if operation == 'verify-existing':
        require(auth['state_kind'] == 'owned-existing' and auth['local_user'] == subject_key(identity)
                and isinstance(auth['expected_account_sha256'], str) and HEX.fullmatch(auth['expected_account_sha256'])
                and auth['password_sha256'] is None)
    else:
        require(auth['state_kind'] in ('fresh-synthetic', 'fresh-new') and auth['local_user'] is None
                and auth['expected_account_sha256'] is None and isinstance(auth['password_sha256'], str)
                and HEX.fullmatch(auth['password_sha256']))
    return auth


def subject_key(identity):
    return sha((identity['issuer'] + '\0' + identity['subject']).encode()) + '@sso.invalid'


def implementation_sha(files):
    require(all(isinstance(files.get(name), bytes) and files[name]
                for name in IMPLEMENTATION_FILES), 'Complete Seafile implementation required')
    return sha(b'\0'.join(files[name] for name in IMPLEMENTATION_FILES))


def explicit_owner(values, realm):
    """An explicit immutable subject, never first user/email/default promotion."""
    subject = values.get('KEYCLOAK_OWNER_SUBJECT') or values.get('FIREFLY_OWNER_SUBJECT')
    require(isinstance(subject, str) and subject and subject.strip() == subject)
    require(not values.get('KEYCLOAK_OWNER_SUBJECT') or not values.get('FIREFLY_OWNER_SUBJECT')
            or values['KEYCLOAK_OWNER_SUBJECT'] == values['FIREFLY_OWNER_SUBJECT'],
            'Selected explicit shared subjects differ')
    domain = values.get('DOMAIN', '')
    require(isinstance(domain, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain)
            and '..' not in domain, 'Selected shared issuer domain invalid')
    require(realm.get('realm') == 'webservices' and isinstance(realm.get('users'), list))
    users = [user for user in realm['users'] if user.get('id') == subject]
    require(len(users) == 1, 'Explicit shared subject must resolve exactly once')
    user = users[0]
    require(user.get('enabled') is True and not user.get('requiredActions'),
            'Explicit shared owner is disabled or onboarding')
    for key, source in (('username', 'KEYCLOAK_OWNER_USERNAME'), ('email', 'KEYCLOAK_OWNER_EMAIL')):
        require(not values.get(source) or values[source] == user.get(key),
                'Explicit shared owner source differs')
    email = user.get('email')
    require(isinstance(email, str) and email == email.strip().lower() and len(email) <= 225
            and re.fullmatch(r'[^\s@]+@[^\s@]+', email), 'Explicit contact address invalid')
    require(isinstance(user.get('username'), str) and user['username'], 'Explicit username absent')
    return dict(issuer='https://keycloak.' + domain + '/realms/webservices',
                subject=subject, remote_user=subject), email


def database_scope(environment):
    keys = ('SEAFILE_MYSQL_DB_CCNET_DB_NAME', 'SEAFILE_MYSQL_DB_SEAFILE_DB_NAME',
            'SEAFILE_MYSQL_DB_SEAHUB_DB_NAME')
    require(all(isinstance(environment.get(key), str) and environment[key] for key in keys))
    port = environment.get('SEAFILE_MYSQL_DB_PORT')
    require(isinstance(port, str) and port.isdecimal() and 1 <= int(port) <= 65535)
    return dict(host=environment['SEAFILE_MYSQL_DB_HOST'], port=int(port),
                user=environment['SEAFILE_MYSQL_DB_USER'], schemas=[environment[key] for key in keys])


def fresh_material(contract, receipt_sha, marker_sha, data_class, identity, email,
                   database, files, password, nonce):
    """Only data; canonical Root binding and actual native proof are still required."""
    require(HEX.fullmatch(receipt_sha) and HEX.fullmatch(marker_sha) and HEX.fullmatch(nonce))
    require(data_class in ('synthetic', 'production'))
    require(isinstance(password, bytes) and len(password) >= 32
            and not any(char in password for char in (b'\0', b'\n', b'\r')))
    auth = dict(version=1, module='seafile', scope_id=marker_sha,
                receipt_sha256=receipt_sha, operation='create-fresh',
                state_kind='fresh-synthetic' if data_class == 'synthetic' else 'fresh-new',
                shared_identity=identity, contact_email=email, local_user=None,
                expected_account_sha256=None, marker_sha256=None,
                implementation_sha256=implementation_sha(files), password_sha256=sha(password),
                fresh_nonce=nonce, database_scope=database)
    marker = encoded({key: auth[key] for key in MARKER_FIELDS})
    auth['marker_sha256'] = sha(marker)
    raw = encoded(auth)
    require(contract.validate_authorization(raw, sha(raw), 'create-fresh', marker,
            b'\0'.join(files[name] for name in IMPLEMENTATION_FILES)) == auth)
    return raw, marker


def native_proof(output, auth):
    """Never accept a log marker without native exit0/stop checked by executor."""
    require(isinstance(output, bytes) and len(output) <= 8 * 1024 * 1024)
    lines = [line[len(PROOF_PREFIX):] for line in output.splitlines() if line.startswith(PROOF_PREFIX)]
    require(len(lines) == 1, 'Exactly one private native proof required')
    proof = strict(lines[0])
    require(isinstance(proof, dict) and set(proof) == PROOF_FIELDS and set(auth) == FIELDS)
    require(type(proof['version']) is int and proof['version'] == 1)
    for key in PROOF_FIELDS - {'local_user', 'account_sha256'}:
        require(proof[key] == auth[key], 'Native proof selected binding differs')
    require(proof['local_user'] == subject_key(auth['shared_identity']))
    require(isinstance(proof['account_sha256'], str) and HEX.fullmatch(proof['account_sha256']))
    if auth['operation'] == 'verify-existing':
        require(proof['account_sha256'] == auth['expected_account_sha256']
                and proof['local_user'] == auth['local_user'], 'Native account CAS differs')
    return proof


def existing_material(contract, fresh_raw, marker, files, proof):
    fresh = strict(fresh_raw)
    require(fresh.get('operation') == 'create-fresh')
    # Re-validate the actual structured proof even for same-process callers.
    require(native_proof(PROOF_PREFIX + encoded(proof), fresh) == proof)
    auth = dict(fresh, operation='verify-existing', state_kind='owned-existing',
                local_user=proof['local_user'], expected_account_sha256=proof['account_sha256'],
                password_sha256=None)
    raw = encoded(auth)
    require(contract.validate_authorization(raw, sha(raw), 'verify-existing', marker,
            b'\0'.join(files[name] for name in IMPLEMENTATION_FILES)) == auth)
    return raw


def projection_owner():
    source = Path(__file__).with_name('native-runtime-projection-owner.py')
    spec = importlib.util.spec_from_file_location('native_seafile_source_owner', source)
    owner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = owner
    spec.loader.exec_module(owner)
    return owner


class PreparingBinding:
    """Read-only, short-lived real Root custody; NOT a persistent execution lease.

    The journal executor must open/check again after stopping temporary native
    units, compare exact pins and CAS, and only then publish derived inputs.
    No method below runs containers, writes authorization or changes receipts.
    """
    def __init__(self, root, release, intent):
        self.o = projection_owner()
        self.sessions = []
        self.closed = False
        try:
            require(not intent.get('domainRuntimeProjections')
                    and not intent.get('nativeSeafileOwnership')
                    and not intent.get('nativeSeafilePreparation'), 'Seafile preparation replay refused')
            for domain in ('platform', 'apps'):
                self.sessions.append(self.o.Session(root, release, intent, domain))
            platform, apps = self.sessions
            require(platform.marker == apps.marker and platform.marker_sha == apps.marker_sha)
            expected = {'mariadb': platform, 'valkey': platform, 'seafile': apps}
            for name, session in expected.items():
                service = session.services.get(name)
                require(isinstance(service, dict) and service.get('lifecycle') == 'daemon'
                        and isinstance(service.get('image'), str)
                        and re.search(r'@sha256:[a-f0-9]{64}$', service['image']),
                        'Complete immutable Seafile support services required')
            self.source = {name: dict(session.services[name]) for name, session in expected.items()}
            seafile = self.source['seafile']
            required_mounts = {'./configs/' + name + ':' + target + ':ro'
                               for name, target in zip(IMPLEMENTATION_FILES, IMPLEMENTATION_TARGETS)}
            required_mounts.add('./configs/' + AUTH_SOURCE + ':/run/seafile-admin/authorization.json:ro')
            require(required_mounts.issubset(set(seafile.get('volumes', [])))
                    and 'seafile_files:/shared' in seafile.get('volumes', [])
                    and seafile.get('entrypoint') == ['/bin/bash', '/runtime-entrypoint.sh']
                    and not seafile.get('command'), 'Exact native Seafile input/action layout required')
            with self.o.p.subtree(apps.release, 'runtime') as fd:
                self.aggregate, self.aggregate_pin = self.o.p.read_at(fd, 'stack.env', private=True)
            with self.o.p.subtree(apps.release, 'runtime/configs') as fd:
                selected = self.o.p.config_mounts(self.source)
                require(selected.count(AUTH_SOURCE) == 1)
                selected.remove(AUTH_SOURCE) # This owning Main action produces it BEFORE projection.
                try:
                    self.o.p.read_at(fd, AUTH_SOURCE, private=True)
                except FileNotFoundError:
                    pass
                else:
                    raise Refused('Caller-supplied Seafile ownership input refused')
                self.files, self.directories, self.config_pins = self.o.p.read_tree(fd, selected)
                self.realm, self.realm_pin = self.o.p.read_at(fd, self.o.p.IDP_REALM)
            self.values = self.o.p.env_values(self.aggregate)
            require(not self.values.get('SEAFILE_ADMIN_AUTHORIZATION_SHA256'),
                    'Caller-supplied Seafile authorization pin refused')
            self.identity, self.email = explicit_owner(self.values, self.o.p.strict(self.realm))
            denied = [form for key, value in self.values.items() if self.o.p.root_only(key, ()) and value
                      for form in self.o.p.secret_forms(value)]
            _, owner_passwords = self.o.p.owner_import_material(apps.release)
            require(not any(form in body for body in self.files.values() for form in [*denied, *owner_passwords]),
                    'Root/owner secret in native preparation configuration')
            self.pins = {session.domain: session.custody for session in self.sessions}
            self.receipt_sha = apps.cas
            self.marker_sha, self.data_class = apps.marker_sha, apps.manifest['storageScope']['dataClass']
            implementation_sha(self.files)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        require(not self.closed)
        for session in self.sessions:
            session.verify()
        session = self.sessions[-1]
        with self.o.p.subtree(session.release, 'runtime') as fd:
            body, pin = self.o.p.read_at(fd, 'stack.env', private=True)
        require(body == self.aggregate and pin == self.aggregate_pin, 'Seafile source environment changed')
        with self.o.p.subtree(session.release, 'runtime/configs') as fd:
            selected = self.o.p.config_mounts(self.source)
            selected.remove(AUTH_SOURCE)
            try:
                self.o.p.read_at(fd, AUTH_SOURCE, private=True)
            except FileNotFoundError:
                pass
            else:
                raise Refused('Caller-supplied Seafile ownership input appeared')
            files, directories, pins = self.o.p.read_tree(fd, selected)
            realm, realm_pin = self.o.p.read_at(fd, self.o.p.IDP_REALM)
        require((files, directories, pins) == (self.files, self.directories, self.config_pins)
                and realm == self.realm and realm_pin == self.realm_pin, 'Seafile selected source changed')

    def close(self):
        if not self.closed:
            for session in reversed(self.sessions):
                session.close()
            self.closed = True
