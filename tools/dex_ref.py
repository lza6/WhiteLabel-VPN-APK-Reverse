import struct,zipfile,sys,re,bisect

def uleb(b,o):
    r=0;s=0
    while True:
        x=b[o];o+=1;r|=(x&0x7f)<<s;s+=7
        if x<0x80:return r,o

def index_dex(buf):
    n=struct.unpack_from('<I',buf,0x38)[0]; so=struct.unpack_from('<I',buf,0x3c)[0]
    strs=[]; smap={}
    for i in range(n):
        off=struct.unpack_from('<I',buf,so+4*i)[0]
        _,o=uleb(buf,off); e=buf.index(b'\x00',o)
        s=buf[o:e].decode('utf-8','replace'); strs.append(s); smap.setdefault(s,i)
    tds=struct.unpack_from('<I',buf,0x40)[0]; tdo=struct.unpack_from('<I',buf,0x44)[0]
    types=[struct.unpack_from('<I',buf,tdo+4*i)[0] for i in range(tds)]
    cds=struct.unpack_from('<I',buf,0x60)[0]; cdo=struct.unpack_from('<I',buf,0x64)[0]
    methods=[]
    for i in range(cds):
        class_idx=struct.unpack_from('<I',buf,cdo+32*i)[0]
        cd_off=struct.unpack_from('<I',buf,cdo+32*i+24)[0]
        cname=strs[types[class_idx]]
        if cd_off==0: continue
        o=cd_off; sf,o=uleb(buf,o); inf,o=uleb(buf,o); dm,o=uleb(buf,o); vm,o=uleb(buf,o)
        for _ in range(sf): _,o=uleb(buf,o); _,o=uleb(buf,o)
        for cnt in (dm,vm):
            mi=0
            for _ in range(cnt):
                d,o=uleb(buf,o); mi+=d; a,o=uleb(buf,o); co,o=uleb(buf,o)
                if co: methods.append((co,cname,mi))
    methods.sort()
    # method name from method_ids
    mids=struct.unpack_from('<I',buf,0x58)[0]; mido=struct.unpack_from('<I',buf,0x5c)[0]
    def mname(i):
        try:
            cls,proto,name=struct.unpack_from('<HHI',buf,mido+8*i)
            return strs[name]
        except: return '?'
    return strs,smap,methods,mname

def scan(apk,needles):
    z=zipfile.ZipFile(apk); res=[]
    for nm in sorted(z.namelist()):
        if not (nm.startswith('classes') and nm.endswith('.dex')): continue
        buf=z.read(nm); strs,smap,methods,mname=index_dex(buf)
        offs=[m[0] for m in methods]
        for nd in needles:
            for s,i in smap.items():
                if nd not in s: continue
                b=struct.pack('<H',i)
                for m in re.finditer(b'\x1a[\x00-\xff]'+re.escape(b),buf):
                    k=bisect.bisect_right(offs,m.start())-1
                    if k>=0:
                        co,cname,mi=methods[k]
                        res.append((nm,cname,mname(mi),s))
    return res

if __name__=='__main__':
    apk=sys.argv[1]; nd=sys.argv[2].split(',')
    r=scan(apk,nd)
    seen=set()
    for nm,c,m,s in r:
        if (c,m) in seen: continue
        seen.add((c,m)); print(f'{nm}\t{c}\t{m}\t<-{s}')
