# Black-box survey of GNU objdump's ARCv2 decoder (majors 4-7 general operations).
# Output: one line per (major, sub, selector, F, format) that objdump decodes: mnemonic, operand shape,
# the -M option set that decoded it (first of cpu=hs, cpu=hs,dsp, cpu=em, cpu=em,dsp) and W when objdump
# warns that it guessed the opcode class.
# A=r4 B=r6 C=r8 (AA/BB/CC: printed as a register pair), n = immediate.
import probe,re,sys
W='Warning: disassembly may be wrong due to guessed opcode class choice. Use -M<class[,class]> to select the correct opcode class(es).'
RUNS=[('hs',None),('hs','dsp'),('em',None),('em','dsp')]
def shape(t):
    warn=W in t
    t=t.replace(W,'').strip()
    if not t or t.startswith('.word'): return None
    m,_,ops=t.partition(' ')
    for r,n in (('r4r5','AA'),('r6r7','BB'),('r8r9','CC'),('r4','A'),('r6','B'),('r8','C')):
        ops=re.sub(r'\b%s\b'%r,n,ops)
    ops=re.sub(r'-?0x[0-9a-f]+|-?\d+','n',ops)
    ops=re.sub(r'\[[a-z_][a-z_0-9]*\]','[aux]',ops)
    return (m,ops,warn)
# 0z/1z: formats 0/1 with a = 0, recorded when they decode differently from a = 4 (two-operand forms)
FORMS=[(0,0,'0'),(1,0,'1'),(2,0,'2'),(3,0,'3r'),(3,1,'3u'),(0,0,'0z'),(1,0,'1z')]
def enc(maj,sub,F,fmt,M,a,b,c):
    if fmt==3: a=(M<<5)|1      # condition eq
    if fmt==2: a=a&63
    return (maj<<27)|((b&7)<<24)|((b>>3)<<12)|(F<<15)|(fmt<<22)|(sub<<16)|(c<<6)|a
rows=[]
for maj in (4,5,6,7):
  for sub in range(64):
    keys=[(None,None)]
    if sub==0x2f: keys=[('sop',a) for a in range(63)]+[('zop',b) for b in range(64)]
    for kind,sel in keys:
      for F in (0,1):
        ws=[]
        for fmt,M,lab in FORMS:
          if kind=='sop':
            if fmt>1: ws.append(None); continue
            w=enc(maj,sub,F,fmt,M,sel,6,8)
          elif kind=='zop':
            if fmt>1: ws.append(None); continue
            w=enc(maj,sub,F,fmt,M,0x3f,sel,8)
          else:
            w=enc(maj,sub,F,fmt,M,0 if lab.endswith('z') else 4,6,8)
          ws.append(w)
        # per format, the first option set that decodes it
        per=[None]*len(FORMS)
        for cpu,ex in RUNS:
          if all(p is not None or w is None for p,w in zip(per,ws)): break
          r=probe.dis([w or 0 for w in ws],size=32,cpu=cpu,extra=ex)
          for i,(w,(l,t)) in enumerate(zip(ws,r)):
            if w is None or per[i] is not None: continue
            sh=shape(t)
            if sh: per[i]=(sh,cpu+('+'+ex if ex else ''))
        for i in (5,6):
          if per[i] and per[i-5] and (per[i][0][0],per[i][0][1].replace('rn','A',1))==per[i-5][0][:2]:
            per[i]=None
        for (fmt,M,lab),p in zip(FORMS,per):
          if p:
            (m,ops,warn),src=p
            rows.append('%d %02x %s %d %s %s|%s|%s%s'%(maj,sub,('-' if kind is None else '%s%02x'%(kind,sel)),F,lab,m,ops,src,' W' if warn else ''))
open(sys.argv[1],'w').write('\n'.join(rows)+'\n')
