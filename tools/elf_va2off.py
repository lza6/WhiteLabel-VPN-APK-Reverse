import lief,struct,sys
b=open(sys.argv[1],'rb').read(); f=lief.parse(b)
segs=[(s.virtual_address,s.virtual_address+s.physical_size,s.file_offset) for s in f.segments]
def va2off(va):
    for vs,ve,fo in segs:
        if vs<=va<ve: return fo+(va-vs)
    return None
if __name__=='__main__':
    for a in sys.argv[2:]:
        va=int(a,16); o=va2off(va)
        print(hex(va),'->',hex(o) if o else None, hex(struct.unpack_from('<Q',b,o)[0]) if o and o+8<=len(b) else '')
