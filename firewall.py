from scapy.all import IP, TCP

class MockFirewall:
  def __init__(self):
    #
    self.rules = []

  def add_rule(self, source_ip_start, source_ip_end, dest_ip_start, dest_ip_end, port_start, port_end, action):
    # Rules will relate to IP, protocol, and port
    rule = {
      # Rules can have range of IP addresses, ports
      'source_ip_start': source_ip_start,
      'source_ip_end': source_ip_end,
      'dest_ip_start': dest_ip_start,
      'dest_ip_end': dest_ip_end,
      'port_start': port_start,
      'port_end': port_end,
      'action': action  # what to do with packets that satisfy these rules
    }
    self.rules.append(rule)

  def process_packet(self, packet):
    # Check to see if packet should be allowed or rejected
    for rule in self.rules:
      source_ip_range = packet[IP].src >= rule['source_ip_start'] and packet[IP].src <= rule['source_ip_end']
      dest_ip_range = packet[IP].dst >= rule['dest_ip_start'] and packet[IP].dst <= rule['dest_ip_end']
      port_range = packet[TCP].dport >= rule['port_start'] and packet[TCP].dport <= rule['port_end']
      if source_ip_range and dest_ip_range and port_range:
        if rule['action'] == 'reject':
          return "Rejected"
      return "Allowed"

# Example usage:
firewall = MockFirewall()
firewall.add_rule(
  source_ip_start="192.168.1.2",
  source_ip_end="192.168.1.9",
  dest_ip_start="192.168.1.1",
  dest_ip_end="192.168.1.6",
  port_start=80, 
  port_end=90,
  action='reject'
)

# Should return Allowed
packet = IP(src="192.168.1.5", dst="192.168.1.3") / TCP(dport=91)
result = firewall.process_packet(packet)
print(result)

# Should return Rejected
packet = IP(src="192.168.1.5", dst="192.168.1.3") / TCP(dport=86)
result = firewall.process_packet(packet)
print(result)