#!/opt/homebrew/bin/python3
# SPDX-License-Identifier: MPL-2.0
"""Synthetic credentials only; never logs the password or challenge cookie."""
import base64, json, os, sys
from pathlib import Path
lines=Path(sys.argv[-1]).read_text().splitlines()
user,password=(lines+['',''])[:2]
mode=os.environ.get('ARKOVPN_AUTH_MODE','password')
if mode.startswith('totp_'):
    from totp_auth import authenticate
    try:
        config=json.loads(Path(os.environ['ARKOVPN_TOTP_CONFIG']).read_text())
        accepted=authenticate(user,password,mode,config,os.environ)
    except Exception:
        sys.exit(1)
    sys.exit(2 if accepted is None else 0 if accepted else 1)
valid=user=='lab'
if mode=='static':
    parts=password.split(':')
    try: valid=valid and len(parts)==3 and parts[0]=='SCRV1' and base64.b64decode(parts[1])==b'lab-secret' and base64.b64decode(parts[2])==b'123456'
    except Exception: valid=False
elif mode=='dynamic':
    if password.startswith('CRV1::'):
        valid=valid and password=='CRV1::lab-state::123456'
    else:
        reason=os.environ.get('auth_failed_reason_file'); control=os.environ.get('auth_control_file')
        if valid and password=='lab-secret' and reason and control:
            Path(reason).write_text('CRV1:R:lab-state:bGFi:Enter test token')
            Path(control).write_text('0')
            sys.exit(2)
        valid=False
else: valid=valid and password=='lab-secret'
sys.exit(0 if valid else 1)
