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
    for ip, protocol, port, packet in self.configs:
      result = self.firewall.process_packet(packet)
      packet_sent_count += 1
      self.results.append((ip, protocol, port, result))
    ip_rules = []
    protocol_rules = []
    port_rules = []
    # IP is blocked if it is always rejected
    for desired_ip in self.ips:
      filtered_configs = [(ip, protocol, port, result) for ip, protocol, port, result in self.results if ip == desired_ip]
      ip_in_rule = True
      for config in filtered_configs:
        if config[3] == "Allowed":
          ip_in_rule = False
          break
      if ip_in_rule:
        ip_rules.append(desired_ip)
    # Protocol is blocked if it is always rejected
    for desired_protocol in self.protocols:
      filtered_configs = [(ip, protocol, port, result) for ip, protocol, port, result in self.results if protocol == desired_protocol]
      protocol_in_rule = True
      for config in filtered_configs:
        if config[3] == "Allowed":
          protocol_in_rule = False
          break
      if protocol_in_rule:
        protocol_rules.append(desired_protocol)
    # Protocol is blocked if it is always rejected
    for desired_port in self.ports:
      filtered_configs = [(ip, protocol, port, result) for ip, protocol, port, result in self.results if port == desired_port]
      port_in_rule = True
      for config in filtered_configs:
        if config[3] == "Allowed":
          port_in_rule = False
          break
      if port_in_rule:
        port_rules.append(desired_port)
    return sorted(ip_rules), sorted(protocol_rules), sorted(port_rules), packet_sent_count
          




