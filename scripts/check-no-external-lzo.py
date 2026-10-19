#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Check full ELF symbols, not only dynamic exports; run before symbol stripping."""
import argparse, os, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--nm',default=os.environ.get('LLVM_NM','/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native/llvm/bin/llvm-nm'));a=p.parse_args()
s=subprocess.check_output([a.nm,'--defined-only','--demangle',str(a.library)],text=True)
if re.search(r'\b(?:T|t|W|w)\s+(?:_?lzo\w*|_?__lzo\w*)(?:\s|$)',s):raise SystemExit('EXTERNAL_LZO_SYMBOL_PRESENT')
if 'CompressLZOAsym::decompress(' not in s or 'lzo_asym_impl::lzo1x_decompress_safe(' not in s:raise SystemExit('BUILTIN_LZO_DECODER_MISSING')
print('PASS: built-in LZO decoder present; no external LZO symbols:',a.library)
