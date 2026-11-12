import zipfile,sys,io,re
import lief
for p in sys.argv[1:]:
    z=zipfile.ZipFile(p); print('='*10,p)
    for i in z.infolist():
        if not (i.filename.endswith('.so') and 'arm64' in i.filename): continue
        b=z.read(i.filename)
        try:
            f=lief.parse(bytes(b))
        except Exception as e:
            print('  ',i.filename,'parse fail',e); continue
        syms=[s.name for s in f.exported_functions if s.name.startswith('Java_')]
        if syms: print(f"  {i.filename.split('/')[-1]:<36} JNI={len(syms)}  {syms[:6]}")
