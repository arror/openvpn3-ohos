#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Disposable DER/PFX/client-chain interoperability fixtures, outside the repository."""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
from server import Lab, Handler


def material(work, name, password=''):
    return {'base64': base64.b64encode((work / name).read_bytes()).decode(),
            'password': password, 'passwordProvided': bool(password), 'outputPassword': ''}


def prepare(lab):
    work = lab.work
    lab.ssl('x509', '-in', 'ca.crt', '-outform', 'DER', '-out', 'ca.der')
    lab.ssl('x509', '-in', 'client.crt', '-outform', 'DER', '-out', 'client.der')
    lab.ssl('pkcs8', '-topk8', '-nocrypt', '-in', 'client.key', '-outform', 'DER', '-out', 'client-key.der')
    lab.ssl('pkcs12', '-export', '-in', 'client.crt', '-inkey', 'client.key', '-certfile', 'ca.crt',
            '-out', 'client.pfx', '-passout', 'pass:certificate-lab-password')
    lab.ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'intermediate.key', '-out', 'intermediate.csr', '-subj', '/CN=Import test intermediate')
    (work / 'intermediate.ext').write_text('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
    lab.ssl('x509', '-req', '-in', 'intermediate.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
            '-out', 'intermediate.crt', '-days', '2', '-extfile', 'intermediate.ext')
    lab.ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'chain-client.key', '-out', 'chain-client.csr', '-subj', '/CN=Import chain client')
    (work / 'chain-client.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n')
    lab.ssl('x509', '-req', '-in', 'chain-client.csr', '-CA', 'intermediate.crt', '-CAkey', 'intermediate.key', '-CAcreateserial',
            '-out', 'chain-client.crt', '-days', '2', '-extfile', 'chain-client.ext')
    lab.ssl('pkcs12', '-export', '-in', 'chain-client.crt', '-inkey', 'chain-client.key', '-certfile', 'intermediate.crt',
            '-out', 'chain-client.pfx', '-passout', 'pass:certificate-lab-password')
    cases = {
        'import_der': [material(work, name) for name in ['ca.der', 'client.der', 'client-key.der']],
        'import_pfx': [material(work, 'client.pfx', 'certificate-lab-password')],
        'import_chain': [material(work, 'ca.der'), material(work, 'chain-client.pfx', 'certificate-lab-password')]
    }
    for name, files in cases.items():
        lab.add(name)
        lab.cases[-1]['certificateMaterials'] = files
    manifest = {'version': 1, 'host': lab.host, 'control': f'http://{lab.host}:{lab.port}', 'token': lab.token, 'cases': lab.cases}
    (work / 'manifest.json').write_text(json.dumps(manifest))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=21180)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    lab = Lab(args.host, args.port, args.work)
    prepare(lab)
    server = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    server.lab = lab
    print('CERTIFICATE_LAB_READY ' + str(lab.work / 'manifest.json'), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
        server.server_close()
