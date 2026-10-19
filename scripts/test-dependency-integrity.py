#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Corrupt cached archives must be rejected before extraction; no network required."""
import os, shutil, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
cmake=os.environ.get('CMAKE_BIN') or shutil.which('cmake') or '/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native/build-tools/cmake/bin/cmake'
env=os.environ.copy()
for name in ['OPENVPN3_SRC','CC','CXX','CFLAGS','CXXFLAGS','LDFLAGS','CMAKE_TOOLCHAIN_FILE']:env.pop(name,None)
with tempfile.TemporaryDirectory(prefix='ovpn-dependency-integrity-') as directory:
 work=Path(directory)
 # Fetch script: an existing bad archive must never be unpacked.
 deps=work/'fetch';deps.mkdir();(deps/'openssl-3.5.0.tar.gz').write_bytes(b'injected corrupt archive')
 result=subprocess.run(['bash',str(root/'scripts/00-fetch-deps.sh')],env={**env,'DEPS_SRC':str(deps)},capture_output=True,text=True)
 assert result.returncode!=0 and 'SHA256 mismatch' in result.stdout+result.stderr,result.stdout+result.stderr
 assert not (deps/'openssl/src/Configure').exists()
 for component in ['OpenVPN','Asio']:
  source=work/component;source.mkdir();shutil.copyfile(root/'CMakeLists.txt',source/'CMakeLists.txt');(source/'deps').mkdir()
  if component=='OpenVPN':archive=source/'deps/openvpn3-3.11.7.tar.gz'
  else:
   core=source/'deps/openvpn3-release-3.11.7';core.mkdir();(core/'CMakeLists.txt').write_text('# test marker, never compiled\n')
   archive=source/'deps/asio-1.24.0.tar.gz'
  archive.write_bytes(b'injected corrupt archive')
  result=subprocess.run([cmake,'-S',str(source),'-B',str(source/'build')],env=env,capture_output=True,text=True)
  assert result.returncode!=0 and component+' archive SHA256 mismatch' in result.stdout+result.stderr,result.stdout+result.stderr
print('Dependency integrity regressions passed: 3 (fetch script, OpenVPN, Asio cached archive corruption)')
