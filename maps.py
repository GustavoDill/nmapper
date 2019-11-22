import re
class Port():
	def __init__(self, port, protocol, status, service):
		self.port = port; self.status = status; self.protocol = protocol; self.service = service
class Map():
	def __init__(self, mapstring):
		self.IP = re.search("Nmap scan report for (192\\.168\\.\\d{1,3}\\.\\d{1,3})", mapstring).group(1)
		try:
			self.Manufacturer = re.search("MAC Address: ([\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+) \\(([\\w \\-,\\d]+)\\)", mapstring).group(2)
		except:
			self.Manufacturer = "Unknown"
		try:
			self.OSRunning = re.search("Running: ([\\w \\-,\\d\\(\\).\\|]+)", mapstring).group(1)
		except:
			self.OSRunning = "Unknown"
		try:
			self.MACAddress = re.search("MAC Address: ([\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+:[\\d\\w]+) \\(([\\w \\-,\\d]+)\\)", mapstring).group(1)
		except:
			self.MACAddress = "Unknown"
		try:
			self.OSDetails = re.search("OS details: ([\\w \\-,\\d\\(\\).]+)", mapstring).group(1)
		except:
			self.OSDetails = "Unknown"
		self.Ports = []
		try:
			for p in re.search("PORT +STATE SERVICE\\n([\\w\\d/ \\-\\n]+)\\nMAC Address", mapstring).group(1).split('\n'):
				self.Ports.append(Port(re.search("(\\d+)/\\w+", p).group(1), re.search("\\d+/(\\w+)", p).group(1), re.search("\\d+/\\w+ *(\\w+)", p).group(1), re.search("\\d+/\\w+ *\\w+ *(\\w+)", p).group(1)))
		except:
			pass
	def getTabs(self, port):
		if (int(len(port.port + "/" + port.protocol) / 8) == 0):
			return "\t\t"
		elif (int(len(port.port + "/" + port.protocol) / 8) == 1):
			return "\t"
		elif (int(len(port.port + "/" + port.protocol) / 8) == 2):
			return ""
	def printDetails(self):
		print("IP:\t" + self.IP)
		print("MAC:\t" + self.MACAddress)
		print("Man:\t" + self.Manufacturer)
		print("OS:\t" + self.OSRunning)
		print("OS Det:\t" + self.OSDetails)
		if (len(self.Ports) > 0):
			print("PORT\t\tSTATE\tSERVICE")
			for x in self.Ports:
				print(x.port + "/" + x.protocol + self.getTabs(x) + x.status + "\t" + x.service)
		else:
			print("No open ports found")
def load(file):
	f = open(file, "r")
	a = f.read().replace("\r", "")
	f.close()
	a = re.search("Nmap scan report for 192\\.168\\.\\d{1,3}\\.\\d{1,3}\n[\n\\w:\\- /\\d\\.\\(\\),|]+Network Distance: \\d+ \\w+\n", a).group()
	maps = []
	s = ""
	for x in a.split('\n'):
		if (x == ""):
			maps.append(Map(s[0:len(s)-1]))
			s = ""
		else:
			s += x + "\n"
	return maps