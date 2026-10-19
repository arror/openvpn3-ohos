#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Close only the temporary lab probe tabs, preserving all other browser tabs."""
import json, re, subprocess, time
from pathlib import Path
HDC='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc'
DEVICE='/data/local/tmp/arkovpn-browser-layout.json'
LOCAL=Path('/tmp/arkovpn-browser-layout.json')

def shell(*args):return subprocess.run([HDC,'shell',*args],capture_output=True,text=True,timeout=30).stdout

def bounds(node):
    values=re.findall(r'-?\d+',node.get('attributes',{}).get('bounds',''))
    return list(map(int,values)) if len(values)==4 else None

def nodes(tree):
    if isinstance(tree,dict):
        yield tree
        for key,value in tree.items():
            if key!='attributes':yield from nodes(value)
    elif isinstance(tree,list):
        for value in tree:yield from nodes(value)

def snapshot():
    result=shell('uitest','dumpLayout','-b','com.huawei.hmos.browser','-p',DEVICE)
    if 'saved to:' not in result: raise RuntimeError('BROWSER_LAYOUT_UNAVAILABLE:'+result.strip())
    subprocess.run([HDC,'file','recv',DEVICE,str(LOCAL)],capture_output=True,check=True,timeout=30)
    return json.loads(LOCAL.read_text())

def cleanup(already_overview=False):
    tree=snapshot()
    if not already_overview:
        control=next((node for node in nodes(tree) if node.get('attributes',{}).get('id')=='medium_btn_in_homepage'),None)
        if not control:raise RuntimeError('BROWSER_TAB_CONTROL_NOT_VISIBLE')
        x,y,r,b=bounds(control);shell('uitest','uiInput','click',str((x+r)//2),str((y+b)//2))
    closed=0
    while closed<250:
        tree=snapshot();target=None
        for card in nodes(tree):
            if not card.get('attributes',{}).get('id','').startswith('tabPage_'):continue
            if not any(re.fullmatch(r'(?:10\.247\.0\.1|\[fd42:247::1\])/[0-9a-f]{24}',node.get('attributes',{}).get('text','')) for node in nodes(card)):continue
            box=bounds(card)
            if not box:continue
            for node in nodes(card):
                attributes=node.get('attributes',{});close=bounds(node)
                if (attributes.get('clickable')=='true' and attributes.get('type')=='Row' and close and
                    close[2]==box[2] and close[0]>=box[2]-110 and close[1]>=box[1] and close[3]<=box[1]+110):
                    target=close;break
            if target:break
        if not target:break
        x,y,r,b=target;shell('uitest','uiInput','click',str((x+r)//2),str((y+b)//2));closed+=1
        if closed % 10 == 0:print('LAB_TABS_CLEANED',closed,flush=True)
        time.sleep(.15)
    print('LAB_BROWSER_TABS_CLOSED',closed)
    shell('uitest','uiInput','keyEvent','Home')
    return closed

if __name__=='__main__':
    import sys
    cleanup('--overview' in sys.argv)
