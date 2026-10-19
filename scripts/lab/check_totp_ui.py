#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise production Home UI with real TOTP. OTPs are never printed or saved."""
import argparse, json, re, subprocess, time, urllib.request
from pathlib import Path
HDC='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc'
BUNDLE='com.arror.ovpn'

class UiTest:
    def __init__(self,work,poll=None,output=None,handshake_only=False,unguarded=False):
        self.work=work;self.manifest=json.loads((work/'manifest.json').read_text())
        self.poll=poll;self.handshake_only=handshake_only;self.guarded=not unguarded
        self.output=work/(output or 'ui-results');self.output.mkdir(exist_ok=True,mode=0o700)
        self.results=[]
        self.server_log=work/'totp_dynamic_ui.log'
        self.server_offset=self.server_log.stat().st_size if self.server_log.exists() else 0
    def shell(self,*args,timeout=30):
        result=subprocess.run([HDC,'shell',*args],capture_output=True,text=True,timeout=timeout)
        if result.returncode:raise RuntimeError('HDC_COMMAND_FAILED')
        return result.stdout
    def control(self,operation,name=''):
        request=urllib.request.Request(self.manifest['control']+'/'+operation+'/'+name,headers={'X-Lab-Token':self.manifest['token']})
        with urllib.request.urlopen(request,timeout=15) as response:return json.load(response)
    def nodes(self,tree):
        if isinstance(tree,dict):
            if 'attributes' in tree:yield tree['attributes']
            for key,value in tree.items():
                if key!='attributes':yield from self.nodes(value)
        elif isinstance(tree,list):
            for value in tree:yield from self.nodes(value)
    def layout(self):
        remote='/data/local/tmp/arkovpn-totp-ui.json';local=self.output/'layout-private.json'
        response=self.shell('uitest','dumpLayout','-b',BUNDLE,'-p',remote)
        if 'saved to:' not in response:raise RuntimeError('APP_LAYOUT_UNAVAILABLE')
        subprocess.run([HDC,'file','recv',remote,str(local)],capture_output=True,check=True,timeout=15)
        tree=json.loads(local.read_text());local.unlink()
        return list(self.nodes(tree))
    def find(self,id=None,text=None,tree=None):
        for node in self.layout() if tree is None else tree:
            if id is not None and node.get('id')==id:return node
            if text is not None and node.get('text')==text:return node
        return None
    def wait(self,id=None,text=None,predicate=None,limit=22):
        end=time.monotonic()+limit
        while time.monotonic()<end:
            node=self.find(id,text)
            if node and (predicate is None or predicate(node)):return node
            time.sleep(.2)
        self.trace('wait_failed');self.image('wait-failed')
        raise RuntimeError('UI_WAIT_FAILED:'+str(id or text))
    def click_node(self,node):
        bounds=list(map(int,re.findall(r'-?\d+',node.get('bounds',''))))
        if len(bounds)!=4:raise RuntimeError('UI_BOUNDS_MISSING')
        x,y,r,b=bounds
        self.shell('uitest','uiInput','click',str((x+r)//2),str((y+b)//2))
    def trace(self,action):
        nodes=self.layout()
        visible={n['id']:n.get('text','') for n in nodes if n.get('id') in ['vpnConnectionStatus','vpnNoticeText','vpnChallengeTitle']}
        print('UI '+str(round(time.time(),3))+' '+action+' '+json.dumps(visible,ensure_ascii=False),flush=True)
    def click(self,id=None,text=None):
        print('CLICK '+str(round(time.time(),3))+' '+str(id or text),flush=True)
        self.click_node(self.wait(id,text))
    def status(self,label):return self.wait('vpnConnectionStatus',predicate=lambda node:node.get('text')==label)
    def image(self,name):
        remote='/data/local/tmp/arkovpn-totp-'+name+'.jpeg'
        local=self.output/(name+'.jpeg');local.unlink(missing_ok=True)
        self.shell('snapshot_display','-f',remote)
        subprocess.run([HDC,'file','recv',remote,str(self.output/(name+'.jpeg'))],check=True,capture_output=True,timeout=15)
        self.shell('rm','-f',remote)
        if not local.is_file() or local.stat().st_size<100 or local.read_bytes()[:2]!=b'\xff\xd8':raise RuntimeError('SCREENSHOT_MISSING')
    def check(self,name,condition):
        if not condition:raise RuntimeError(name)
        self.results.append({'name':name,'passed':True});print('PASS '+name,flush=True)
        (self.output/'results.json').write_text(json.dumps(self.results,ensure_ascii=False,indent=2))
    def audit(self,verdict):
        events=self.control('authaudit')['events']
        (self.output/('audit-'+verdict+'.json')).write_text(json.dumps(events,indent=2))
        self.check('server_'+verdict,bool(events) and events[-1]['verdict']==verdict)
    def idle_resources(self):
        self.status('未连接')
        processes=self.shell('ps','-ef')
        interfaces=self.shell('ifconfig')
        self.check('idle_without_extension_or_tun',not any(BUNDLE+':' in row for row in processes.splitlines()) and 'vpn-tun' not in interfaces)
    def dismiss_notice(self):
        node=self.find(text='我知道了')
        if node:self.click_node(node)
    def challenge(self):
        self.dismiss_notice();self.click('vpnPowerButton')
        self.wait('vpnChallengeTitle')
        self.check('power_guard_expected_behind_challenge',str(self.wait('vpnPowerButton').get('enabled')).lower()==('false' if self.guarded else 'true'))
        self.check('empty_input_on_new_challenge',self.wait('vpnChallengeInput').get('text','')=='')
        self.check('empty_submission_disabled',str(self.wait('vpnChallengeSubmit').get('enabled')).lower()=='false')
    def enter(self,code):
        node=self.wait('vpnChallengeInput');x,y,r,b=map(int,re.findall(r'-?\d+',node['bounds']))
        self.shell('uitest','uiInput','inputText',str((x+r)//2),str((y+b)//2),code)
        self.shell('uitest','uiInput','keyEvent','Back')
        self.wait('vpnChallengeSubmit',predicate=lambda n:str(n.get('enabled')).lower()=='true')
    def rejected(self,verdict):
        self.wait('vpnNoticeText',predicate=lambda n:'验证码' in n.get('text','') and '认证失败' in n.get('text',''))
        self.idle_resources();self.audit(verdict)
        self.check('power_guard_expected_behind_notice',str(self.wait('vpnPowerButton').get('enabled')).lower()==('false' if self.guarded else 'true'))
        self.check('challenge_removed_after_rejection',self.find('vpnChallengeInput') is None)
        time.sleep(3)
        self.idle_resources();self.audit(verdict)
        self.check('no_automatic_auth_retry',self.find('vpnChallengeInput') is None)
    def connected(self):
        self.status('已连接');self.audit('accepted')
        self.check('actual_tunnel_http_round_trip',self.control('probe')['ok'])
        self.shell('aa','start','-a','EntryAbility','-b',BUNDLE)
        self.status('已连接');self.image('connected')
    def capture_server_packets(self):
        records=[]
        with self.server_log.open('r') as stream:
            stream.seek(self.server_offset)
            for line in stream:
                packet=re.search(r'UDPv4 (READ|WRITE) \[(\d+)\].*\[AF_INET\]([0-9.]+):(\d+)',line)
                if packet:records.append({'time':re.match(r'^[0-9-]+ [0-9:]+(?: us=[0-9]+)?',line)[0],'direction':packet[1],'bytes':int(packet[2]),'peer':packet[3],'port':int(packet[4])})
        (self.output/'server-packets.json').write_text(json.dumps(records,indent=2))
    def cleanup_connection(self):
        tree=self.layout()
        cancel=self.find('vpnChallengeCancel',tree=tree)
        if cancel:self.click_node(cancel);self.idle_resources();return
        status=self.find('vpnConnectionStatus',tree=tree)
        if status and status.get('text')!='未连接':
            self.dismiss_notice();self.click('vpnPowerButton');self.idle_resources()
    def fixture(self,mode):
        args=['aa','test','-b',BUNDLE,'-m','entry_test','-s','unittest','OpenHarmonyTestRunner','-s','totp_ui',mode,'-s','timeout','60000']
        if self.poll is not None:args+=['-s','poll',str(self.poll)]
        output=self.shell(*args,timeout=45)
        (self.output/('fixture-'+mode+'.log')).write_text(output)
        if not re.search(r'Tests run: 1, Failure: 0, Error: 0, Pass: 1, Ignore: 0',output):raise RuntimeError('FIXTURE_'+mode.upper()+'_FAILED')
    def run(self):
        seeded=False
        trace_file=(self.output/'core-trace.log').open('w')
        trace=subprocess.Popen([HDC,'shell','hilog','-T','OVPN_TRACE'],stdout=trace_file,stderr=subprocess.STDOUT)
        try:
            self.fixture('seed');seeded=True
            self.control('start','totp_dynamic_ui')
            self.shell('aa','start','-a','EntryAbility','-b',BUNDLE)
            self.status('未连接');self.wait(text='TOTP 验收（临时）')
            if self.handshake_only:
                self.challenge();self.enter(self.control('otp','expired')['code']);self.click('vpnChallengeSubmit')
                self.rejected('expired');print('HANDSHAKE_UI_PASSED',flush=True);return
            self.challenge();self.image('challenge')
            self.enter(self.control('otp','wrong')['code']);self.click('vpnChallengeSubmit')
            self.rejected('invalid');self.image('wrong-rejected')
            # A fresh attempt after the wrong code must have a clean input and accept a real code.
            self.challenge();self.enter(self.control('otp','valid')['code']);self.click('vpnChallengeSubmit')
            self.connected();self.click('vpnPowerButton');self.idle_resources()
            # Real elapsed time, unchanged wall clock and 30s TOTP step with +/-1 tolerance.
            self.control('start','totp_dynamic_ui')
            self.challenge();issued=self.control('otp','valid');self.enter(issued['code'])
            start=time.monotonic()
            print('WAIT actual TOTP expiry beyond tolerance window',flush=True)
            while self.control('totpclock')['counter'] < issued['counter']+2:
                if time.monotonic()-start>70:raise RuntimeError('TOTP_EXPIRY_WAIT_FAILED')
                time.sleep(1)
            self.check('real_time_expiry_wait',time.monotonic()-start>15)
            self.wait('vpnChallengeTitle');self.click('vpnChallengeSubmit')
            self.rejected('expired');self.image('expired-rejected')
            self.challenge();self.enter(self.control('otp','valid')['code']);self.click('vpnChallengeSubmit')
            self.connected();self.click('vpnPowerButton');self.idle_resources()
            self.control('start','totp_dynamic_ui')
            self.challenge();self.enter(self.control('otp','valid')['code']);self.click('vpnChallengeCancel')
            self.idle_resources();self.check('cancel_does_not_submit_otp',all(event['verdict']=='challenge' for event in self.control('authaudit')['events']))
            self.challenge();self.click('vpnChallengeCancel');self.idle_resources()
        finally:
            try:
                try:
                    if seeded:self.cleanup_connection()
                    (self.output/'server-audit.json').write_text(json.dumps(self.control('authaudit'),indent=2))
                finally:self.control('stop');self.capture_server_packets()
            finally:
                try:
                    if seeded:self.fixture('cleanup')
                finally:
                    self.shell('rm','-f','/data/local/tmp/arkovpn-totp-ui.json')
                    trace.terminate();trace.wait(timeout=5);trace_file.close()
        print('TOTP_PRODUCTION_UI_PASSED',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--unguarded',action='store_true')
    parser.add_argument('--handshake-only',action='store_true')
    parser.add_argument('--poll',type=int,choices=[2,15]);parser.add_argument('--output')
    args=parser.parse_args();UiTest(args.work,args.poll,args.output,args.handshake_only,args.unguarded).run()
