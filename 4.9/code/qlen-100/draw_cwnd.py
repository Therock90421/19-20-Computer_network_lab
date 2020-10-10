import matplotlib.pyplot as plt

file = open('1.txt')
data = file.readlines()
para_1 = []
para_2 = []
for num in data:
    para_1.append(float(num.split(' ')[0]))
    para_2.append(float(num.split(' ')[6]))
plt.figure
plt.title('qlen-100')
plt.plot(para_1,para_2)
plt.xlim(0.061382688 ,60.061382688 )
plt.xlabel('time')
plt.ylabel('Cwnd')
plt.show()
