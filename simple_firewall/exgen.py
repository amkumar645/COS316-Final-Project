from scapy.all import IP, TCP, UDP
import dns
import random

class ExhaustiveGeneticSolver:
  def __init__(self, ips, protocols, ports, firewall, population_size, generations):
    self.protocols = protocols
    self.ports = ports
    self.ips = ips
    self.current_population = []
    self.configs = []
    # Create a random population of population_size
    for _ in range(population_size):
      random_ip = random.sample(self.ips, 1)[0]
      random_protocol = random.sample(self.protocols, 1)[0]
      random_port = random.sample(self.ports, 1)[0]
      if random_protocol == "TCP":
        packet = IP(src="192.168.0.0", dst=random_ip) / TCP(dport=random_port)
      elif random_protocol == "UDP":
        packet = IP(src="192.168.0.0", dst=random_ip) / UDP(dport=random_port)
      self.current_population.append((random_ip, random_protocol, random_port, packet))
    self.firewall = firewall
    self.results = []
    self.generations = generations
    self.population_size = population_size
  
  def solve_firewall(self):
    allowed_flag = False
    configs_used = set()
    remaining_ips = self.ips
    remaining_protocols = self.protocols
    remaining_ports = self.ports
    packet_sent_count = 0
    ip_rules = set()
    protocol_rules = set()
    port_rules = set()
    changed_rule = [""] * self.population_size
    for gen in range(self.generations):
      next_generation = []
      previous_rules = changed_rule
      changed_rule = []
      for index in range(len(self.current_population)):
        ip, protocol, port, packet = self.current_population[index]
        result = self.firewall.process_packet(packet)
        packet_sent_count += 1
        configs_used.add((ip, protocol, port))
        # if packet allowed, then we learn nothing
        if result == "Allowed":
          # only need 1 allowed to figure out all rules
          if allowed_flag: 
            continue
          allowed_flag = True
          # Add all possible children that change one attribute
          # All possible IP changes
          for next_ip in self.ips:
            if protocol == "TCP":
              packet_new = IP(src="192.168.0.0", dst=next_ip) / TCP(dport=port)
            if protocol == "UDP":
              packet_new = IP(src="192.168.0.0", dst=next_ip) / UDP(dport=port)
            if (next_ip, protocol, port) not in configs_used:
              next_generation.append((next_ip, protocol, port, packet_new))
              changed_rule.append("ip")
          # All possible protocol changes
          for next_protocol in self.protocols:
            if next_protocol == "TCP":
              packet_new = IP(src="192.168.0.0", dst=ip) / TCP(dport=port)
            if next_protocol == "UDP":
              packet_new = IP(src="192.168.0.0", dst=ip) / UDP(dport=port)
            if (ip, next_protocol, port) not in configs_used:
              next_generation.append((ip, next_protocol, port, packet_new))
              changed_rule.append("protocol")
          # All possible port changes
          for next_port in self.ports:
            if protocol == "TCP":
              packet_new = IP(src="192.168.0.0", dst=ip) / TCP(dport=next_port)
            if protocol == "UDP":
              packet_new = IP(src="192.168.0.0", dst=ip) / UDP(dport=next_port)
            if (ip, protocol, next_port) not in configs_used:
              next_generation.append((ip, protocol, next_port, packet_new))
              changed_rule.append("port")
        # if packet rejected, then whatever last change was is guaranteed rule (unless first gen)
        elif result == "Rejected":
          if gen == 0:
            continue
          if previous_rules[index] == "ip":
            ip_rules.add(ip)
            # once ip is known rule, never use it again
            try:
              remaining_ips.remove(ip)
            except ValueError as e:
              continue
          elif previous_rules[index] == "protocol":
            protocol_rules.add(protocol)
            # once protocol is known rule, never use it again
            try:
              remaining_protocols.remove(protocol)
            except ValueError as e:
              continue
          elif previous_rules[index] == "port":
            port_rules.add(port)
            # once port is known rule, never use it again
            try:
              remaining_ports.remove(port)
            except ValueError as e:
              continue
      self.current_population = next_generation
      if gen > 0:
        return sorted(list(ip_rules)), sorted(list(protocol_rules)), sorted(list(port_rules)), packet_sent_count