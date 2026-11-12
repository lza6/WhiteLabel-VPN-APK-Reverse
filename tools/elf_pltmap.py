import lief,sys,re
from capstone import *
path=sys.argv[1]; b=open(path,'rb').read(); f=lief.parse(b)
got={r.address:(r.symbol.name if r.symbol else '?') for r in f.pltgot_relocations}
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
out={}
for addr in range(0x1ba10,0x1c1e0,16):
    ins=list(md.disasm(b[addr:addr+16],addr))
    if not ins or ins[0].mnemonic!='adrp' or len(ins)<2: continue
    m1=re.search(r'#(0x[0-9a-f]+)',ins[0].op_str); m2=re.search(r'#(0x[0-9a-f]+)',ins[1].op_str)
    if not(m1 and m2): continue
    va=int(m1.group(1),16)+int(m2.group(1),16)
    out[addr]=got.get(va,hex(va))
for k,v in sorted(out.items()): print(hex(k),v)
