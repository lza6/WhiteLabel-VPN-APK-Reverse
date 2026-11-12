import sys,zipfile
from loguru import logger; logger.remove()
from androguard.core.dex import DEX
apk=sys.argv[1]; needle=sys.argv[2]
z=zipfile.ZipFile(apk)
for nm in sorted(n for n in z.namelist() if n.startswith('classes') and n.endswith('.dex')):
    d=DEX(z.read(nm))
    for c in d.get_classes():
        cn=c.get_name()
        hits=[]
        for m in c.get_methods():
            code=m.get_code()
            if not code: continue
            for ins in code.get_bc().get_instructions():
                o=ins.get_output() or ''
                if needle in o: hits.append((m.get_name()+m.get_descriptor(), o)); break
        if hits:
            print('==',cn)
            for h in hits: print('   ',h[0],'|',h[1][:150])
