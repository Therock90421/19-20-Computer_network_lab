import matplotlib.pyplot as plt

file = open('qlen.txt')
data = file.readlines()
para_1 = []
para_2 = []
for num in data:
    para_1.append(float(num.split(',')[0]))
    para_2.append(float(num.split(',')[1]))
plt.figure
plt.title('qlen-10')
plt.plot(para_1,para_2)
plt.xlim(1586364540.056659,1586364545.056659)
plt.xlabel('time',fontsize = 20)
plt.ylabel('Qlen',fontsize = 20)
plt.show()
