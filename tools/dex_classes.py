import sys,zipfile,re
from loguru import logger; logger.remove()
from androguard.core.dex import DEX
apk,pat=sys.argv[1],sys.argv[2]
z=zipfile.ZipFile(apk); out=set()
for nm in sorted(n for n in z.namelist() if n.startswith('classes') and n.endswith('.dex')):
    d=DEX(z.read(nm))
    for c in d.get_classes():
        n=c.get_name()
        if re.search(pat,n,re.I): out.add(n)
for n in sorted(out): print(n)
print('total',len(out))
