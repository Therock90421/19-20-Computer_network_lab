import matplotlib.pyplot as plt
import numpy as np


def readfile(filename):
	data_list = []
	data_num = 0
	line_num = 2200
	with open(filename, 'r') as f:
		for line in f.readlines():
			linestr = line.strip('\n')
			data_tuple = linestr.split(':')
			data_list.append(data_tuple)
			data_num += 1

	return data_list, data_num

data_list,num = readfile("./cwnd.dat")
x_list = [t[0] for t in data_list]
y_list = [t[1] for t in data_list]

x_list = list(map(float, x_list))
y_list = list(map(float, y_list))

plt.plot(x_list, y_list)
plt.show()

