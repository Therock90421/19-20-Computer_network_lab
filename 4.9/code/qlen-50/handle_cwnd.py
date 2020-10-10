
with open('cwnd.txt','r') as f1, open('1.txt','w') as f2:
    for line in f1.readlines():
        line = line.strip()
        if "10.0.1.11:51540 10.0.2.22:5001" in line:
            f2.write(line + '\n')
