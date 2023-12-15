from scapy.all import IP

class MockFirewall:
  def __init__(self):
    # IP: list of 50 options
    # Protocol: List of 3 options
    # Port: list of 100 options
    self.rules = []

  def add_rule(self, ips, protocols, ports, action):
    # Rules will relate to IP, protocol, and port
    rule = {
      'ips': ips,
      'protocols': protocols,
      'ports': ports,
      'action': action  # what to do with packets that satisfy any of these rules (always reject)
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
      if protocol_condition and ip_condition and port_condition:
        if rule['action'] == 'reject':
          return "Rejected"
    return "Allowed"