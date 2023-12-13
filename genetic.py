from scapy.all import IP, TCP, UDP
import dns
import random

class GeneticSolver:
  def __init__(self, domains, protocols, ports, firewall, population_size, generations):
    self.domains = domains
    self.protocols = protocols
    self.ports = ports
    self.ips = []
    for domain in domains:
      self.ips.append(dns.get_ip_address(domain))
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
          # Add 3 children into next gen, each changing ip, protocol, or port
          # Only change IP
          random_ip = random.sample(remaining_ips, 1)[0]
          if protocol == "TCP":
            packet_1 = IP(src="192.168.0.0", dst=random_ip) / TCP(dport=port)
          if protocol == "UDP":
            packet_1 = IP(src="192.168.0.0", dst=random_ip) / UDP(dport=port)
          if (random_ip, protocol, port) not in configs_used:
            next_generation.append((random_ip, protocol, port, packet_1))
            changed_rule.append("ip")
          # Only change protocol
          random_protocol = random.sample(remaining_protocols, 1)[0]
          if random_protocol == "TCP":
            packet_2 = IP(src="192.168.0.0", dst=ip) / TCP(dport=port)
          if random_protocol == "UDP":
            packet_2 = IP(src="192.168.0.0", dst=ip) / UDP(dport=port)
          if (ip, random_protocol, port) not in configs_used:
            next_generation.append((ip, random_protocol, port, packet_2))
            changed_rule.append("protocol")
          # Only change port
          random_port = random.sample(remaining_ports, 1)[0]
          if protocol == "TCP":
            packet_3 = IP(src="192.168.0.0", dst=ip) / TCP(dport=random_port)
          if protocol == "UDP":
            packet_3 = IP(src="192.168.0.0", dst=ip) / UDP(dport=random_port)
          if (ip, protocol, random_port) not in configs_used:
            next_generation.append((ip, protocol, random_port, packet_3))
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
    return sorted(list(ip_rules)), sorted(list(protocol_rules)), sorted(list(port_rules)), packet_sent_count
          




