from scapy.all import IP, TCP, UDP, ICMP
import dns

class MockFirewall:
  def __init__(self):
    #
    self.rules = []

  def add_rule(self, ips, protocols, ports, action):
    # Rules will relate to IP, protocol, and port
    rule = {
      # Rules can have range of IP addresses, ports
      'ips': ips,
      'protocols': protocols,
      'ports': ports,
      'action': action  # what to do with packets that satisfy any of these rules
    }
    self.rules.append(rule)

  def process_packet(self, packet):
    # Check to see if packet should be allowed or rejected
    for rule in self.rules:
      protocol_condition = False
      ip_condition = False
      port_condition = False
      # Check protocol
      if packet.payload.name in rule['protocols']:
        protocol_condition = True
      if packet[IP].dst in rule['ips']:
        ip_condition = True
      if packet[packet.payload.name].dport in rule['ports']:
        port_condition = True
      if protocol_condition or ip_condition or port_condition:
        if rule['action'] == 'reject':
          return "Rejected"
    return "Allowed"

list_of_ips = dns.list_of_ips
list_of_ports = list(range(100))
list_of_protocols = [
  "TCP", "UDP", "ICMP"
]

# Example usage:
firewall = MockFirewall()
firewall.add_rule(
  ips = list_of_ips[0:10],
  ports = list_of_ports[0:10],
  protocols = list_of_protocols[1:2],
  action='reject'
)

# Should return Allowed
packet = IP(src="192.168.0.0", dst=list_of_ips[11]) / TCP(dport=91)
result = firewall.process_packet(packet)
print(result)

# Should return Rejected (due to IP)
packet = IP(src="192.168.0.0", dst=list_of_ips[1]) / TCP(dport=86)
result = firewall.process_packet(packet)
print(result)

# Should return Rejected (due to protocol)
packet = IP(src="192.168.0.0", dst=list_of_ips[11]) / UDP(dport=91)
result = firewall.process_packet(packet)
print(result)

# Should return Rejected (due to port)
packet = IP(src="192.168.0.0", dst=list_of_ips[11]) / TCP(dport=0)
result = firewall.process_packet(packet)
print(result)