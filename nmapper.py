from os import system
from sys import argv as args
import maps
def nmap(ips, outfile):
	iplist = ""
	for x in ips:
		iplist += " " + x
	system("nmap -O" + iplist + " > " + outfile)
if (args[1] == "--help"):
	print("Usage:\nnmapper.py type start end\nExample nmapper.py 192.168.10 1 255")
else:
	t = args[1]
	s = args[2]
	e = args[3]
	ips = []
	for i in range(int(s), int(e)):
		ips.append(t + "." + str(i))
	nmap(ips, "maps.txt")
	print()
	for m in maps.load('maps.txt'):
		m.printDetails()
		print('\n')