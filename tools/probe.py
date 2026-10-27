import struct, subprocess, os, tempfile
SLOT=os.path.expanduser('~/.cache/ghidra-rare-scratch/community-verify/ARCv2/tools/slotdis')
D=os.path.dirname(os.path.abspath(__file__))
def dis(words, cpu='hs', size=None, extra=None, limm=(0x1234,0x5678)):
    """words: list of ints. 32-bit if > 0xffff or size==32. returns list of (len,text)"""
    fn=os.path.join(D,'p_%d.bin'%os.getpid())
    with open(fn,'wb') as f:
        for w in words:
            if (size or (32 if w>0xffff else 16))==32:
                f.write(struct.pack('<HHHH',w>>16,w&0xffff,limm[0],limm[1]))
            else:
                f.write(struct.pack('<HHHH',w,limm[0],limm[1],0))
    m='cpu='+cpu+((','+extra) if extra else '')
    out=subprocess.run([SLOT,'arc:ARCv2','8',fn,'-M',m],capture_output=True,text=True).stdout.splitlines()
    os.unlink(fn)
    r=[]
    for l in out:
        x=l.split(' ',2); r.append((int(x[1]),x[2] if len(x)>2 else ''))
    return r
