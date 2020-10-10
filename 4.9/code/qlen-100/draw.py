import matplotlib.pyplot as plt

file = open('qlen.txt')
data = file.readlines()
para_1 = []
para_2 = []
for num in data:
    para_1.append(float(num.split(',')[0]))
    para_2.append(float(num.split(',')[1]))
plt.figure
plt.title('qlen-100')
plt.plot(para_1,para_2)
plt.xlim(1586366495.786659,1586366535.786659)
plt.xlabel('time',fontsize = 20)
plt.ylabel('Qlen',fontsize = 20)
plt.show()
