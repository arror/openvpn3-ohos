#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Ephemeral OpenVPN interoperability lab. Keys/manifests live outside the repository."""
import argparse, base64, hashlib, http.server, json, os, re, secrets, signal, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

OPENVPN = '/opt/homebrew/sbin/openvpn'
OPENSSL = '/opt/homebrew/opt/openssl@3/bin/openssl'
ROOT = Path(__file__).resolve().parent

class Lab:
    def __init__(self, host, port, work, udp_trace=False, compression_server=None):
        self.host, self.port, self.work = host, port, work
        self.token = json.loads((work/'manifest.json').read_text())['token'] if (work/'manifest.json').exists() else secrets.token_hex(24)
        self.relay = None; self.udp_trace = udp_trace
        self.compression_server = compression_server
        self.process = None; self.current = ''; self.lock = threading.Lock()
        self.specs = {}; self.cases = []; self.totp_modes = {}; self.totp_config = None
        self.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.prepare()

    def ssl(self, *args):
        subprocess.run([OPENSSL, *args], cwd=self.work, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def prepare(self):
        if not (self.work/'ca.key').exists():
            self.ssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.crt','-days','2','-subj','/CN=ArkOvpn disposable CA')
            for name, role in [('server','serverAuth'),('client','clientAuth')]:
                self.ssl('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=arkovpn-'+name)
                (self.work/(name+'.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+role+'\n')
                self.ssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','2','-extfile',name+'.ext')
            self.ssl('pkey','-in','client.key','-aes-256-cbc','-passout','pass:lab-key-password','-out','client-encrypted.key')
            subprocess.run([OPENVPN,'--genkey','secret',str(self.work/'tls.key')],check=True,capture_output=True)
            subprocess.run([OPENVPN,'--genkey','tls-crypt-v2-server',str(self.work/'v2-server.key')],check=True,capture_output=True)
            subprocess.run([OPENVPN,'--tls-crypt-v2',str(self.work/'v2-server.key'),'--genkey','tls-crypt-v2-client',str(self.work/'v2-client.key')],check=True,capture_output=True)
        self.add('udp_certificate')
        self.add('tcp_certificate', transport='tcp')
        self.add('tls_auth', server=['tls-auth tls.key 0'], client=['key-direction 1',self.block('tls-auth','tls.key')])
        self.add('tls_crypt', server=['tls-crypt tls.key'], client=[self.block('tls-crypt','tls.key')])
        self.add('tls_crypt_v2', server=['tls-crypt-v2 v2-server.key'], client=[self.block('tls-crypt-v2','v2-client.key')])
        self.add('aes128_gcm', cipher='AES-128-GCM')
        self.add('chacha20_poly1305', cipher='CHACHA20-POLY1305')
        self.add('aes256_cbc', cipher='AES-256-CBC', legacy=True, server=['auth SHA256'],client=['cipher AES-256-CBC','auth SHA256'])
        self.add('tls12',server=['tls-version-min 1.2','tls-version-max 1.2'])
        self.add('tls13',server=['tls-version-min 1.3'],client=['tls-version-min 1.3'])
        self.add('encrypted_private_key', key='client-encrypted.key', challenge='lab-key-password')
        self.add('routes_dns_mtu', server=['push "route 10.248.0.0 255.255.0.0"','push "route 10.249.0.0 255.255.0.0 net_gateway"','push "dhcp-option DNS 10.247.0.1"','push "dhcp-option DOMAIN-SEARCH lab.invalid"','tun-mtu 1400','push "tun-mtu 1400"'])
        self.add('ipv6_tunnel', ipv6=True, server=['ifconfig-ipv6 fd42:247::1/64 fd42:247::2','ifconfig-ipv6-pool fd42:247::1000/64','push "route-ipv6 fd42:248::/64"'])
        self.add('redirect_gateway', server=['push "redirect-gateway def1"'])
        self.add('reconnect', action='restart')
        self.add('system_revoke', action='revoke')
        self.add('renegotiation', server=['reneg-sec 5 5'], client=['reneg-sec 5'], action='renegotiate')
        for compression in ['stub-v2','lz4-v2','lzo']:
            self.add('compress_'+compression.replace('-','_'),server=['allow-compression asym','compress '+compression,'push "compress '+compression+'"'],client=['compress '+compression])
        for compression in ['lzo','lz4','lz4-v2']:
            self.add('compressed_'+compression.replace('-','_'),server=['allow-compression yes','compress '+compression,'push "compress '+compression+'"','verb 9'],client=['compress '+compression])
        for name, mode, password, challenge, expected in [
            ('userpass','password','lab-secret','','connected'),
            ('static_challenge','static','lab-secret','123456','connected'),
            ('dynamic_challenge','dynamic','lab-secret','123456','connected'),
            ('wrong_password','password','wrong','','error')]:
            client=['auth-user-pass']
            if mode=='static':client += ['static-challenge "Enter test token" 0']
            self.add(name,server=['auth-user-pass-verify '+str(ROOT/'auth_peer.py')+' via-file','setenv ARKOVPN_AUTH_MODE '+mode],client=client,challenge=challenge,expected=expected)
            self.cases[-1]['username']='lab';self.cases[-1]['password']=password
        self.add('commented_auth_directive',
            server=['auth-user-pass-verify '+str(ROOT/'auth_peer.py')+' via-file', 'setenv ARKOVPN_AUTH_MODE password'],
            client=['# auth-user-pass is supplied by the application', '; auth-user-pass', 'setenv note auth-user-pass'])
        self.cases[-1]['username']='lab';self.cases[-1]['password']='lab-secret'
        self.add('bad_server_name', client=['verify-x509-name wrong-server name'], expected='error')
        self.add('cancel_connecting', client=['remote 192.0.2.1 9 udp'], expected='cancel')
        self.add('password_without_client_cert', server=['verify-client-cert none','auth-user-pass-verify '+str(ROOT/'auth_peer.py')+' via-file'],client=['auth-user-pass','setenv CLIENT_CERT 0'])
        self.cases[-1]['username']='lab';self.cases[-1]['password']='lab-secret'
        profile=self.cases[-1]['profile']
        for tag in ['cert','key']:
            start=profile.index('<'+tag+'>');end=profile.index('</'+tag+'>',start)+len(tag)+3
            profile=profile[:start]+profile[end:]
        self.cases[-1]['profile']=profile
        self.add('unsupported_encrypted_dns', server=['push "dns server 0 address 10.247.0.1:853"','push "dns server 0 transport DoT"'], expected='error')
        self.add('unsupported_system_proxy', server=['push "dhcp-option PROXY_HTTP 10.247.0.1 8080"'], expected='error')
        self.add('connect_stress', action='stress')
        for flavor in ['dynamic','static','password']:
            for result in ['valid','wrong','expired']:
                name='totp_'+flavor+'_'+result
                self.add_totp(name,flavor,result)
        self.add_totp('totp_dynamic_replay','dynamic','replay')
        self.add_totp('totp_dynamic_ui','dynamic','ui')
        manifest={'version':1,'host':self.host,'control':f'http://{self.host}:{self.port}','token':self.token,'cases':self.cases}
        (self.work/'manifest.json').write_text(json.dumps(manifest))

    def add_totp(self,name,flavor,result):
        mode='totp_'+flavor
        path=self.work/(name+'.totp.json')
        self.totp_modes[name]=mode
        client=['auth-user-pass']
        if flavor=='static':client += ['static-challenge "请输入动态验证码" 0']
        self.add(name,server=['auth-user-pass-verify '+str(ROOT/'auth_peer.py')+' via-file',
            'setenv ARKOVPN_AUTH_MODE '+mode,'setenv ARKOVPN_TOTP_CONFIG '+str(path),'verb 6'],
            client=client,expected='error' if result in ['wrong','expired'] else 'connected',action=result,poll_timeout=2)
        self.cases[-1]['username']='lab';self.cases[-1]['password']='lab-secret'

    def block(self, kind, file):
        return f'<{kind}>\n{(self.work/file).read_text()}\n</{kind}>'

    def add(self,name,transport='udp',server=None,client=None,cipher='AES-256-GCM',key='client.key',challenge='',ipv6=False,legacy=False,expected='connected',action='',poll_timeout=2):
        number=len(self.cases); vpnport=21194+number
        server_lines=['dev tun','dev-node unix:'+str(ROOT/'packet_peer.py'),'mode server','tls-server', 'proto '+('tcp4-server' if transport=='tcp' else 'udp4'), 'local '+self.host,'port '+str(vpnport),'ca ca.crt','cert server.crt','key server.key','dh none','ifconfig 10.247.0.1 255.255.255.0','ifconfig-noexec','route-noexec','topology subnet','ifconfig-pool 10.247.0.2 10.247.0.10 255.255.255.0','push "topology subnet"','push "route-gateway 10.247.0.1"','data-ciphers '+cipher,'keepalive 1 5','script-security 2','verb 3']+(server or [])
        self.specs[name]='\n'.join(server_lines)+'\n'
        client_lines=['client','dev tun','proto '+('tcp-client' if transport=='tcp' else 'udp'),'remote '+self.host+' '+str(vpnport),'remote-cert-tls server','server-poll-timeout '+str(poll_timeout), self.block('ca','ca.crt'),self.block('cert','client.crt'),self.block('key',key)]+(client or [])
        if name=='cancel_connecting':client_lines=[x for x in client_lines if not x.startswith('remote '+self.host+' ')]
        self.cases.append({'name':name,'profile':'\n'.join(client_lines)+'\n','username':'','password':'','challenge':challenge,'ipv6':ipv6,'legacy':legacy,'expected':expected,'action':action})

    def stop(self):
        if self.relay:
            self.relay.terminate();self.relay.wait(timeout=4);self.relay=None
        if self.process:
            if self.current.startswith('compressed_'):
                try: os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError: pass # The owned process group is already gone.
            elif self.process.poll() is None: self.process.terminate()
            try:self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
            self.process=None

    def activate(self,name):
        with self.lock:
            self.stop();self.current=name
            executable = OPENVPN
            compressed = name.startswith('compressed_')
            if compressed:
                if self.compression_server is None: raise RuntimeError('COMPRESSION_SERVER_REQUIRED')
                executable = str(self.compression_server)
            if name in self.totp_modes:
                self.totp_config={'secret':base64.b32encode(secrets.token_bytes(20)).decode(),
                    'account':secrets.token_hex(16),'database':str(self.work/'totp-auth.sqlite'),
                    'step':30,'window':1}
                (self.work/(name+'.totp.json')).write_text(json.dumps(self.totp_config))
            else:self.totp_config=None
            spec=self.specs[name]
            if self.udp_trace and name=='totp_dynamic_ui':
                public_port=next(int(line.split()[1]) for line in spec.splitlines() if line.startswith('port '))
                target_port=public_port+2000
                spec=spec.replace(f'port {public_port}\n',f'port {target_port}\n')
            path=self.work/(name+'.conf');path.write_text(spec)
            log=open(self.work/(name+'.log'),'ab',buffering=0)
            env = os.environ.copy()
            if compressed: env['ARKOVPN_PROBE_LARGE'] = '1'
            self.process=subprocess.Popen([executable,'--cd',str(self.work),'--config',str(path)],stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=compressed)
            log.close()
            time.sleep(.2)
            if self.process.poll() is not None:raise RuntimeError('SERVER_START_FAILED:'+name)
            if self.udp_trace and name=='totp_dynamic_ui':
                trace=open(self.work/'udp-trace.jsonl','ab',buffering=0)
                self.relay=subprocess.Popen([sys.executable,str(ROOT/'udp_trace.py'),'--host',self.host,'--listen',str(public_port),'--target',str(target_port)],stdout=trace,stderr=subprocess.STDOUT)
                trace.close();time.sleep(.1)
                if self.relay.poll() is not None:raise RuntimeError('RELAY_START_FAILED')
        return {'ok':True}

    def control(self,op,name):
        if op=='health':return {'ok':True}
        if op=='start':return self.activate(name)
        if op=='restart':return self.activate(self.current)
        if op=='stop':
            with self.lock:self.stop()
            return {'ok':True}
        if op=='authdelay':
            if not self.totp_config or not name.isdigit() or int(name)>5:raise ValueError('INVALID_AUTH_DELAY')
            self.totp_config['response_delay']=int(name)
            (self.work/(self.current+'.totp.json')).write_text(json.dumps(self.totp_config))
            return {'ok':True}
        if op=='otp':
            if not self.totp_config:raise ValueError('TOTP_NOT_ACTIVE')
            import pyotp
            from totp_auth import classify
            now=time.time();counter=int(now//30)
            authenticator=pyotp.TOTP(self.totp_config['secret'],interval=30)
            code=authenticator.at((counter-3)*30 if name=='expired' else now)
            if name=='wrong':
                code=next(str(value).zfill(6) for value in range(100) if classify(self.totp_config['secret'],str(value).zfill(6),now)[1]=='invalid')
            return {'ok':True,'code':code,'counter':counter-3 if name=='expired' else counter,'serverCounter':counter,'expiryWaitMs':max(0,int(((counter+2)*30-now)*1000)+1000),'step':30,'window':1}
        if op=='totpclock':return {'ok':True,'counter':int(time.time()//30),'step':30,'window':1}
        if op=='authaudit':
            if not self.totp_config:return {'ok':False}
            from totp_auth import database
            with database(self.totp_config) as db:
                rows=db.execute('SELECT at,verdict,counter FROM audit WHERE account=? ORDER BY at',(self.totp_config['account'],)).fetchall()
            return {'ok':True,'events':[{'at':r[0],'verdict':r[1],'counter':r[2]} for r in rows]}
        if op=='crashready':
            hdc='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc'
            processes=subprocess.run([hdc,'shell','ps','-ef'],capture_output=True,text=True,timeout=4).stdout
            interfaces=subprocess.run([hdc,'shell','ifconfig'],capture_output=True,text=True,timeout=4).stdout
            (self.work/'crash-ready.json').write_text(json.dumps({'pid':int(name),'processes':processes,'interfaces':interfaces,'time':time.time()}))
            return {'ok':True}
        if op=='probe':
            compression_log=self.work/(self.current+'.log')
            log_offset=compression_log.stat().st_size if self.current.startswith('compressed_') else 0
            nonce=secrets.token_hex(12)
            (self.work/'probe.request').write_text(nonce)
            hdc='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc'
            address='[fd42:247::1]' if name=='ipv6' else '10.247.0.1'
            launch=subprocess.run([hdc,'shell','aa','start','-A','ohos.want.action.viewData','-U','http://'+address+'/'+nonce],capture_output=True,text=True,timeout=4)
            (self.work/'browser-launch.log').write_text(launch.stdout+launch.stderr)
            end=time.monotonic()+5
            while time.monotonic()<end:
                try:
                    reply=json.loads((self.work/'probe.reply').read_text())
                    if reply.get('nonce')==nonce and reply.get('family')==(6 if name=='ipv6' else 4):
                        result={'ok':True,'family':reply['family']}
                        if self.current.startswith('compressed_'):
                            pairs=re.findall(r'(?:LZO|LZ4) compress (\d+) -> (\d+)',compression_log.read_bytes()[log_offset:].decode())
                            packets=[(int(a),int(b)) for a,b in pairs if int(a)>=512 and int(b)<int(a)]
                            if not packets: raise RuntimeError('REAL_COMPRESSED_PACKET_NOT_OBSERVED')
                            result.update(compressedPackets=len(packets),originalBytes=sum(a for a,b in packets),compressedBytes=sum(b for a,b in packets))
                            (self.work/(self.current+'.compression-proof.json')).write_text(json.dumps({'case':self.current,'nonce':nonce,**result}))
                        return result
                except (FileNotFoundError,ValueError):pass
                time.sleep(.05)
            return {'ok':False}
        raise ValueError('UNKNOWN_CONTROL')

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('X-Lab-Token')!=self.server.lab.token:self.send_error(403);return
        try:
            parts=self.path.strip('/').split('/')
            with (self.server.lab.work/'control-audit.jsonl').open('a') as audit:
                audit.write(json.dumps({'at':time.time(),'event':'request','operation':parts[0],'name':parts[1] if len(parts)>1 else ''})+'\n')
            result=self.server.lab.control(parts[0],parts[1] if len(parts)>1 else '')
            with (self.server.lab.work/'control-audit.jsonl').open('a') as audit:
                audit.write(json.dumps({'at':time.time(),'event':'completed','operation':parts[0],'name':parts[1] if len(parts)>1 else ''})+'\n')
            content=json.dumps(result).encode();self.send_response(200);self.end_headers();self.wfile.write(content)
        except Exception as exc:
            self.send_response(500);self.end_headers();self.wfile.write(str(exc).encode())
    def log_message(self,*args):pass

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--host',required=True);parser.add_argument('--port',type=int,default=21180);parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--udp-trace',action='store_true')
    parser.add_argument('--compression-server',type=Path)
    args=parser.parse_args();os.umask(0o077)
    lab=Lab(args.host,args.port,args.work,args.udp_trace,args.compression_server)
    server=http.server.ThreadingHTTPServer((args.host,args.port),Handler);server.lab=lab
    print('LAB_READY '+str(lab.work/'manifest.json'),flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:lab.stop();server.server_close()
