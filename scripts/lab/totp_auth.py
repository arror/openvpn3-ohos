# SPDX-License-Identifier: MPL-2.0
"""RFC 6238 verifier for the disposable VPN lab. Never records OTPs or secrets."""
import base64, hashlib, hmac, json, secrets, sqlite3, struct, time
from pathlib import Path


def generate(secret, counter, digits=6, algorithm='sha1'):
    key=base64.b32decode(secret.upper(),casefold=True)
    digest=hmac.new(key,struct.pack('!Q',counter),getattr(hashlib,algorithm)).digest()
    offset=digest[-1]&15
    value=struct.unpack('!I',digest[offset:offset+4])[0]&0x7fffffff
    return str(value % (10**digits)).zfill(digits)


def classify(secret, code, now=None, step=30, window=1, digits=6):
    counter=int((time.time() if now is None else now)//step)
    if len(code)!=digits or not code.isascii() or not code.isdigit():return None,'invalid'
    for delta in range(-window,window+1):
        if counter+delta>=0 and hmac.compare_digest(generate(secret,counter+delta,digits),code):return counter+delta,'accepted'
    for delta in range(window+1,11):
        if counter>=delta and hmac.compare_digest(generate(secret,counter-delta,digits),code):return None,'expired'
    return None,'invalid'


def database(config):
    db=sqlite3.connect(config['database'],timeout=5)
    db.execute('CREATE TABLE IF NOT EXISTS used (account TEXT, counter INTEGER, PRIMARY KEY(account,counter))')
    db.execute('CREATE TABLE IF NOT EXISTS challenges (account TEXT, state TEXT, username TEXT, issued REAL, used INTEGER, PRIMARY KEY(account,state))')
    db.execute('CREATE TABLE IF NOT EXISTS audit (account TEXT, at REAL, verdict TEXT, counter INTEGER)')
    return db


def audit(db, config, verdict, counter=None):
    db.execute('INSERT INTO audit VALUES (?,?,?,?)',(config['account'],time.time(),verdict,counter))


def authenticate(username,password,mode,config,environment):
    delay=config.get('response_delay',0)
    if delay and mode=='totp_dynamic' and password.startswith('CRV1::'):
        with database(config) as db:audit(db,config,'response_received')
        time.sleep(delay)
    with database(config) as db:
        if username!='lab':audit(db,config,'bad_username');return False
        if mode=='totp_dynamic':
            if not password.startswith('CRV1::'):
                if password!='lab-secret':audit(db,config,'bad_password');return False
                reason=environment.get('auth_failed_reason_file');control=environment.get('auth_control_file')
                if not reason or not control:audit(db,config,'missing_deferred_files');return False
                state=secrets.token_hex(16)
                db.execute('INSERT INTO challenges VALUES (?,?,?,?,0)',(config['account'],hashlib.sha256(state.encode()).hexdigest(),username,time.time()))
                audit(db,config,'challenge')
                Path(reason).write_text('CRV1:R:'+state+':'+base64.b64encode(username.encode()).decode()+':请输入动态验证码')
                Path(control).write_text('0')
                return None
            parts=password.split(':',4)
            if len(parts)!=5:audit(db,config,'invalid_response');return False
            state=hashlib.sha256(parts[2].encode()).hexdigest()
            row=db.execute('SELECT username,issued,used FROM challenges WHERE account=? AND state=?',(config['account'],state)).fetchone()
            if not row or row[0]!=username or row[2] or time.time()-row[1]>120:
                audit(db,config,'bad_state');return False
            db.execute('UPDATE challenges SET used=1 WHERE account=? AND state=?',(config['account'],state))
            code=parts[4]
        elif mode=='totp_static':
            try:
                prefix,encoded_password,encoded_code=password.split(':')
                if prefix!='SCRV1' or base64.b64decode(encoded_password,validate=True)!=b'lab-secret':raise ValueError()
                code=base64.b64decode(encoded_code,validate=True).decode('ascii')
            except (ValueError,UnicodeError):audit(db,config,'invalid_response');return False
        else:
            if not password.startswith('lab-secret'):audit(db,config,'bad_password');return False
            code=password[len('lab-secret'):]
        counter,verdict=classify(config['secret'],code,step=config['step'],window=config['window'])
        if counter is not None:
            try:db.execute('INSERT INTO used VALUES (?,?)',(config['account'],counter))
            except sqlite3.IntegrityError:verdict='replayed'
        audit(db,config,verdict,counter)
        return verdict=='accepted'
