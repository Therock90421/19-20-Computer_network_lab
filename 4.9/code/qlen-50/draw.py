import matplotlib.pyplot as plt

file = open('qlen.txt')
data = file.readlines()
para_1 = []
para_2 = []
for num in data:
    para_1.append(float(num.split(',')[0]))
    para_2.append(float(num.split(',')[1]))
plt.figure
plt.title('qlen-50')
plt.plot(para_1,para_2)
plt.xlim(1586365508.358744,1586365528.358744)
plt.xlabel('time',fontsize = 20)
plt.ylabel('Qlen',fontsize = 20)
plt.show()
