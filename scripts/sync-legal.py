#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Synchronize canonical native license metadata/text into the app; --check is read-only."""
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def expected():
    components=json.loads((ROOT/'legal/components.json').read_text())
    source=json.loads((ROOT/'legal/source.json').read_text())
    files={Path('components.json'):json.dumps(components,ensure_ascii=False,indent=2)+'\n',
           Path('source.json'):json.dumps(source,ensure_ascii=False,indent=2)+'\n'}
    for c in components:
        name=c['file'];assert Path(name).name==name
        files[Path(name)]=(ROOT/'LICENSES'/name).read_text()
    files[Path('THIRD_PARTY_NOTICES.md')]=(ROOT/'THIRD_PARTY_NOTICES.md').read_text()
    return files
def main(check, app_root):
    out=app_root/'entry/src/main/resources/rawfile/licenses'
    if not (app_root/'entry').is_dir():raise SystemExit('Set --app-root to an application checkout containing entry/')
    for path,content in expected().items():
        target=out/path
        if check:
            if not target.exists() or target.read_text()!=content:raise SystemExit('LEGAL_RESOURCE_OUT_OF_SYNC: '+str(target))
        else:
            target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content)
    print('Legal resources match canonical source' if check else 'Legal resources synchronized')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--app-root',type=Path,default=ROOT/'ohos');a=p.parse_args();main(a.check,a.app_root)
