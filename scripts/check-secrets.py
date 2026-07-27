#!/usr/bin/env python3
import re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
patterns={
 '生产旁路由地址':r'192\.168\.10\.112',
 '常见订阅token':r'(?i)(token|subscribe)[=:?/&][A-Za-z0-9_-]{16,}',
 'UUID':r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b',
 '私钥标记':r'(?i)(private[-_ ]?key|password)\s*[:=]\s*[^\s{}]{8,}',
}
skip={'.git','build','dist','__pycache__'};bad=[]
for p in ROOT.rglob('*'):
 if not p.is_file() or p.resolve()==Path(__file__).resolve() or any(x in p.parts for x in skip):continue
 try:s=p.read_text()
 except UnicodeDecodeError:continue
 for name,pat in patterns.items():
  if re.search(pat,s):bad.append((str(p.relative_to(ROOT)),name))
if bad:
 for p,n in bad:print(f'{p}: 命中 {n}')
 sys.exit(1)
print('敏感信息扫描通过')

# This script intentionally contains scanner pattern names, so do not scan itself.
