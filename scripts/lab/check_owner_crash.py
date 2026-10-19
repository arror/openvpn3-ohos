#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Check an ohosTest-only SIGSEGV. Production code contains no crash hook."""
import argparse, json, re, subprocess, time
from pathlib import Path
HDC='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc'

def shell(*args, timeout=8):
    return subprocess.run([HDC,'shell',*args],capture_output=True,text=True,timeout=timeout).stdout

def run(work):
    ready=work/'crash-ready.json'
    if ready.exists():ready.unlink()
    with (work/'owner-crash-test.log').open('w') as log:
        runner=subprocess.Popen([HDC,'shell','aa','test','-b','com.arror.ovpn','-m','entry_test','-s','unittest','OpenHarmonyTestRunner','-s','lab','1','-s','crash','kill','-s','timeout','60000'],stdout=log,stderr=subprocess.STDOUT)
        end=time.monotonic()+35
        while not ready.exists() and time.monotonic()<end:
            if runner.poll() is not None:break
            time.sleep(.1)
        if not ready.exists():raise RuntimeError('CRASH_WAS_NOT_ARMED')
        before=json.loads(ready.read_text())
        assert 'vpn-tun' in before['interfaces'],'NO_TUN_BEFORE_CRASH'
        vpn_rows=[row for row in before['processes'].splitlines() if 'com.arror.ovpn:' in row]
        assert vpn_rows,'NO_EXTENSION_BEFORE_CRASH'
        old_pids=[str(before['pid'])]+[row.split()[1] for row in vpn_rows]
        end=time.monotonic()+18
        while time.monotonic()<end:
            processes=shell('ps','-ef'); interfaces=shell('ifconfig')
            rows=[row for row in processes.splitlines() if 'com.arror.ovpn' in row]
            remaining=[row for row in rows if len(row.split())>1 and row.split()[1] in old_pids]
            if not remaining and 'vpn-tun' not in interfaces:
                result={'passed':True,'oldPids':old_pids,'cleanupSeconds':round(time.time()-before['time'],3),'remainingProcesses':rows}
                (work/'owner-crash-result.json').write_text(json.dumps(result,indent=2))
                print(json.dumps(result));break
            time.sleep(.2)
        else:raise RuntimeError('OWNER_DEATH_LEFT_PROCESS_OR_TUN')
        try:runner.wait(timeout=5)
        except subprocess.TimeoutExpired:runner.terminate();runner.wait(timeout=5)
    # Fresh engine starts idle without a stale-session notice, then accepts a new connect intent.
    recovered=shell('aa','test','-b','com.arror.ovpn','-m','entry_test','-s','unittest','OpenHarmonyTestRunner','-s','lab','1','-s','crash','recover','-s','timeout','60000',timeout=70)
    (work/'owner-recovery-test.log').write_text(recovered)
    if not re.search(r'Tests run: 1, Failure: 0, Error: 0, Pass: 1, Ignore: 0',recovered):raise RuntimeError('FRESH_ENGINE_RECOVERY_FAILED')
    print('OWNER_CRASH_AND_RECOVERY_PASSED')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True)
    run(parser.parse_args().work)
