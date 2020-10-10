import matplotlib.pyplot as plt

file1 = open('ping_red.txt')
data1 = file1.readlines()
para_1 = []
para_2 = []
for num in data1:
    para_1.append(float(num.split(',')[0]))
    para_2.append(float(num.split(',')[1]))

file2 = open('ping_codel.txt')
data2 = file2.readlines()
para_3 = []
para_4 = []
for num in data2:
    para_3.append(float(num.split(',')[0]))
    para_4.append(float(num.split(',')[1]))

file3 = open('ping_taildrop.txt')
data3 = file3.readlines()
para_5 = []
para_6 = []
for num in data3:
    para_5.append(float(num.split(',')[0]))
    para_6.append(float(num.split(',')[1]))





plt.figure
plt.title('Ping test with different algorithm')
plt.plot(para_1,para_2,color='red',label='red')
plt.plot(para_3,para_4,color='green',label='codel')
plt.plot(para_5,para_6,color='blue',label='taildrop')
plt.legend()
plt.ylim(0,4000)
plt.xlabel('Packet')
plt.ylabel('Ping')
plt.show()
