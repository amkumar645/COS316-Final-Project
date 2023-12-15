from scapy.all import IP, TCP, UDP

class NaiveSolver:
  def __init__(self, ips, protocols, ports, firewall):
    self.protocols = protocols
    self.ports = ports
    self.ips = ips
    # Create all possible packets from ips, protocols and ports
    self.packets = []
    self.configs = []
    for ip in self.ips:
      for port in self.ports:
        for protocol in self.protocols:
          if protocol == "TCP":
            packet = IP(src="192.168.0.0", dst=ip) / TCP(dport=port)
          elif protocol == "UDP":
            packet = IP(src="192.168.0.0", dst=ip) / UDP(dport=port)
          self.configs.append((ip, protocol, port, packet))
    self.firewall = firewall
    self.results = []
  
  def solve_firewall(self):
    packet_sent_count = 0
    rejected_packets = []
    for ip, protocol, port, packet in self.configs:
      result = self.firewall.process_packet(packet)
      packet_sent_count += 1
      if result == "Rejected":
        rejected_packets.append((ip, protocol, port))
    return rejected_packets, packet_sent_count