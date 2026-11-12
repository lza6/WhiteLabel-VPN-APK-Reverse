import lief,sys,re
from capstone import *
b=open(sys.argv[1],'rb').read()
f=lief.parse(b)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
start=int(sys.argv[2],16); size=int(sys.argv[3])
# resolve adrp+add string refs
for ins in md.disasm(b[start:start+size],start):
    line=f'  {ins.address:x}: {ins.mnemonic:<8}{ins.op_str}'
    if ins.mnemonic=='adrp':
        print(line)
    elif ins.mnemonic in ('add','ldr') and 'x' in ins.op_str:
        # try resolve literal
        try:
            val=int(ins.op_str.split('#')[-1],0)
        except Exception: val=None
        print(line)
    else:
        print(line)
