txt=open('p.txt').readlines()
outputs=[]
w=open('pingout.txt','w') 
for line in txt:
    line=line.replace('64 bytes from 10.0.2.22: icmp_seq=','')
    line=line.replace(' ttl=63 time=',',')
    line=line.replace(' ms','')
    w.write(line)

