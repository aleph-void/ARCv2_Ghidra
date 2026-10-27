# Black-box survey: the auxiliary register names GNU objdump prints for "lr r0,[limm]" (cpu=hs, cpu=em).
# Output lines: <number-hex> <name> (the hs name when both name it).
import probe,struct,subprocess,re,sys
w=(4<<27)|(0x2a<<16)|(62<<6)
names={}
for cpu in ('em','hs'):
  for base in (0,0x10000,0x3c000):
    fn='aux_%d.bin'%base
    with open(fn,'wb') as f:
      for v in range(base,base+0x10000):
        f.write(struct.pack('<HHHH',w>>16,w&0xffff,v>>16,v&0xffff))
    out=subprocess.run([probe.SLOT,'arc:ARCv2','8',fn,'-M','cpu='+cpu],capture_output=True,text=True).stdout.splitlines()
    for i,l in enumerate(out):
      m=re.search(r'\[([a-z_][a-z0-9_]*)\]',l)
      if m: names[base+i]=m.group(1)
open(sys.argv[1],'w').write(''.join('%x %s\n'%(k,v) for k,v in sorted(names.items())))
