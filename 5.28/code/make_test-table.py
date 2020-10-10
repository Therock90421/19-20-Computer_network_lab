source = "forwarding-table.txt"
test = "test-table.txt"

i = 0

with open(source, 'r') as fr:
	with open(test, 'w') as fw:
		data = fr.readlines()

		for line in data:
			ip, mask, port = line.split(" ")
			if i == 0:
				ip_new = ip
				line_new = line
				i = 1
				continue
			if ip != ip_new:
				fw.write(line_new)
			ip_new = ip
			line_new = line
