import sys,zipfile
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
apk,target=sys.argv[1],sys.argv[2]
t=target.replace('.','/')
if not t.startswith('L'): t='L'+t
if not t.endswith(';'): t=t+';'
z=zipfile.ZipFile(apk)
for nm in sorted(n for n in z.namelist() if n.startswith('classes') and n.endswith('.dex')):
    d=DEX(z.read(nm))
    for c in d.get_classes():
        if c.get_name()!=t: continue
        print('===',nm,c.get_name(),'super=',c.get_superclassname())
        for m in c.get_methods():
            code=m.get_code()
            print('--',m.get_name(),m.get_descriptor(),'code=',bool(code))
            if not code: continue
            for ins in code.get_bc().get_instructions():
                s=ins.get_output()
                if s: print('    ',s[:220])
