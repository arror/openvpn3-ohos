#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Verify source notices, offline full texts and canonical product dependency scope."""
import hashlib, json, os, subprocess, sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
files=[root/'CMakeLists.txt',root/'index.d.ts']+[p for d in ['src','scripts'] for p in (root/d).rglob('*') if p.suffix in ['.cpp','.hpp','.inc','.sh','.py','.cjs'] and '__pycache__' not in p.parts]
missing=[str(p.relative_to(root)) for p in files if 'SPDX-License-Identifier:' not in p.read_text()[:600]]
if missing:raise SystemExit('SOURCE_LICENSE_NOTICE_MISSING: '+str(missing))
for name in ['CMakeLists.txt','scripts/00-fetch-deps.sh','scripts/04-build-all-deps.sh','scripts/test-host.sh']:
 text=(root/name).read_text()
 if 'liblzo2.a' in text or '-llzo2' in text or 'brew --prefix lzo' in text or '03-build-lzo' in text:raise SystemExit('PRODUCT_LZO_DEPENDENCY: '+name)
items=json.loads((root/'legal/components.json').read_text());assert len({i['id'] for i in items})==len(items)
assert next(i for i in items if i['id']=='openvpn')['license']=='MPL-2.0'
assert not any(i['id']=='lzo' for i in items)
for item in items:
 assert (root/'LICENSES'/item['file']).stat().st_size>500,item
app=Path(os.environ.get('ARKOVPN_APP_ROOT',root/'ohos'))
if (app/'entry').is_dir():subprocess.run([sys.executable,str(root/'scripts/sync-legal.py'),'--check','--app-root',str(app)],check=True)
else:print('Application resource sync not checked: no external app checkout')
print('PASS source SPDX coverage:',len(files),'files; canonical component licenses:',len(items))
