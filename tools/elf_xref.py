import lief,sys,struct
from capstone import *
path,targets=sys.argv[1],sys.argv[2].split('|')
b=open(path,'rb').read(); f=lief.parse(b)
segs=[(s.virtual_address,s.virtual_address+s.physical_size,s.file_offset) for s in f.segments if s.type==lief.ELF.Segment.TYPE.LOAD]
def va2off(va):
    for vs,ve,fo in segs:
        if vs<=va<ve: return fo+(va-vs)
    return None
# locate target strings
addr_of={}
for t in targets:
    i=b.find(t.encode())
    if i<0: print('MISSING',t); continue
    # find va for this file offset
    va=None
    for vs,ve,fo in segs:
        if fo<=i<fo+(ve-vs): va=vs+(i-fo); break
    addr_of[t]=va
    print('str',t,'file',hex(i),'va',hex(va))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
text=None
for s in f.sections:
    if s.name=='.text': text=(s.virtual_address,s.virtual_address+s.size)
print('text',hex(text[0]),hex(text[1]))
# scan adrp/add pairs
code=b[text[0]:text[1]]
last={}
hits={}
for ins in md.disasm(code,text[0]):
    if ins.mnemonic=='adrp':
        try: last[ins.operands[0].reg]=ins.operands[1].imm
        except Exception: pass
    elif ins.mnemonic=='add' and len(ins.operands)==3:
        try:
            dst,src,imm=ins.operands[0].reg,ins.operands[1].reg,ins.operands[2].imm
        except Exception: continue
        if src in last:
            va=last[src]+imm
            for t,tv in addr_of.items():
                if tv==va: hits.setdefault(t,[]).append(ins.address)
for t,v in hits.items(): print('XREF',t,[hex(x) for x in v[:12]],'total',len(v))
