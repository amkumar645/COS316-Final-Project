from scapy.all import IP, TCP, UDP
import random

class SmallScaleGeneticSolver:
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
    configs_used = set()
    rejected_packets = []
    packet_sent_count = 0
    for gen in range(self.generations):
      next_generation = []
      for index in range(len(self.current_population)):
        ip, protocol, port, packet = self.current_population[index]
        result = self.firewall.process_packet(packet)
        packet_sent_count += 1
        configs_used.add((ip, protocol, port))
        # if packet rejected, keep track
        if result == "Rejected":
          rejected_packets.append((ip, protocol, port))
        if gen == self.generations - 1:
          continue
        # Keep all packets alive
        # Add 3 children into next gen, each changing ip, protocol, or port
        # Only change IP
        random_ip = random.sample(self.ips, 1)[0]
        if protocol == "TCP":
          packet_1 = IP(src="192.168.0.0", dst=random_ip) / TCP(dport=port)
        if protocol == "UDP":
          packet_1 = IP(src="192.168.0.0", dst=random_ip) / UDP(dport=port)
        if (random_ip, protocol, port) not in configs_used:
          next_generation.append((random_ip, protocol, port, packet_1))
          configs_used.add((random_ip, protocol, port))
        # Only change protocol
        random_protocol = random.sample(self.protocols, 1)[0]
        if random_protocol == "TCP":
          packet_2 = IP(src="192.168.0.0", dst=ip) / TCP(dport=port)
        if random_protocol == "UDP":
          packet_2 = IP(src="192.168.0.0", dst=ip) / UDP(dport=port)
        if (ip, random_protocol, port) not in configs_used:
          next_generation.append((ip, random_protocol, port, packet_2))
          configs_used.add((ip, random_protocol, port))
        # Only change port
        random_port = random.sample(self.ports, 1)[0]
        if protocol == "TCP":
          packet_3 = IP(src="192.168.0.0", dst=ip) / TCP(dport=random_port)
        if protocol == "UDP":
          packet_3 = IP(src="192.168.0.0", dst=ip) / UDP(dport=random_port)
        if (ip, protocol, random_port) not in configs_used:
          next_generation.append((ip, protocol, random_port, packet_3))   
          configs_used.add((ip, protocol, random_port))     
      self.current_population = next_generation
    return rejected_packets, packet_sent_count