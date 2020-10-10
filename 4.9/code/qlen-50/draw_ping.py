import matplotlib.pyplot as plt

file = open('pingout.txt')
data = file.readlines()
para_1 = []
para_2 = []
for num in data:
    para_1.append(float(num.split(',')[0]))
    para_2.append(float(num.split(',')[1]))
plt.figure
plt.title('qlen-50')
plt.plot(para_1,para_2)
plt.xlim(0,150)
plt.ylim(0,600)
plt.xlabel('Packet',fontsize = 20)
plt.ylabel('Ping',fontsize = 20)
plt.show()
