# Black-box survey: which long-immediate / discarded-destination combinations objdump accepts for
# the general operations (format 0), per (major, sub-opcode, F). Output: maj sub F rejected-combos
import probe,sys
COMBOS={'a62':(62,6,8),'b62':(4,62,8),'c62':(4,6,62),'a62b62':(62,62,8),'a62c62':(62,6,62),'b62c62':(4,62,62),'a62b62c62':(62,62,62)}
def enc(maj,sub,F,a,b,c,fmt=0): return (maj<<27)|((b&7)<<24)|((b>>3)<<12)|(F<<15)|(fmt<<22)|(sub<<16)|(c<<6)|a
out=[]
for maj in (4,5,6,7):
  for sub in range(64):
    if sub==0x2f: continue
    for F in (0,1):
      base=[enc(maj,sub,F,4,6,8)]
      ws=base+[enc(maj,sub,F,*v) for v in COMBOS.values()]
      res=[None]*len(ws)
      for cpu,ex in (('hs',None),('hs','dsp'),('em',None),('em','dsp')):
        r=probe.dis(ws,size=32,cpu=cpu,extra=ex)
        for i,(l,t) in enumerate(r):
          if res[i] is None and not t.startswith('.word'): res[i]=t
      if res[0] is None: continue
      rej=[k for k,t in zip(COMBOS,res[1:]) if t is None]
      if rej: out.append('%d %02x %d %s'%(maj,sub,F,' '.join(rej)))
open(sys.argv[1],'w').write('\n'.join(out)+'\n')
