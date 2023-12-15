import dns
from firewall import MockFirewall
import random
from naive import NaiveSolver
from ssgen import SmallScaleGeneticSolver
from exgen import ExhaustiveGeneticSolver
from datetime import datetime

def random_selection(input_list):
  # make sure there is at least one that is approved
  num_elements_to_select = random.randint(1, len(input_list) - 1)
  selected_elements = random.sample(input_list, num_elements_to_select)
  return sorted(selected_elements)

def rule_accuracy(true_rules, predicted_rules):
  correct_count = 0
  for rule in true_rules:
    if rule in predicted_rules:
      correct_count +=1
  return correct_count / len(true_rules)

def jaccard_similarity(true_rules, predicted_rules):
  true_set = set(true_rules)
  predicted_set = set(predicted_rules)
  intersection = len(true_set.intersection(predicted_set))
  union = len(true_set.union(predicted_set))
  # Handle the case where both sets are empty to avoid division by zero
  if union == 0:
    return 0.0
  similarity = intersection / union
  return similarity

list_of_possible_ips = dns.list_of_ips
list_of_possible_ports = list(range(1000))
list_of_possible_protocols = [
  "TCP", "UDP"
]

# Create a randomized firewall
# randomly select number of IPs from list
blocked_ips = sorted(random_selection(list_of_possible_ips))
blocked_protocols = sorted(random_selection(list_of_possible_protocols))
blocked_ports = sorted(random_selection(list_of_possible_ports))
print("Number of blocked IPs:", len(blocked_ips))
print("Number of blocked protocols:", len(blocked_protocols))
print("Number of blocked ports:", len(blocked_ports))
print()
firewall = MockFirewall()
firewall.add_rule(
  ips = blocked_ips,
  ports = blocked_ports,
  protocols = blocked_protocols,
  action='reject'
)

list_of_possible_dests = dns.most_popular_sites
# Create Naive Solver
start_time = datetime.now()
naive_solver = NaiveSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall
)
solved_ips, solved_protocols, solved_ports, num_packets_sent = naive_solver.solve_firewall()
end_time = datetime.now()
print("Naive Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(blocked_ips + blocked_protocols + blocked_ports, solved_ips + solved_protocols + solved_ports)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(blocked_ips + blocked_protocols + blocked_ports, solved_ips + solved_protocols + solved_ports)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent)
print("Time used:", end_time - start_time)
print()

# Create SSGen Solver
start_time = datetime.now()
ssgen_solver = SmallScaleGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall,
  population_size=5000,
  generations=50
)
solved_ips_ssgen, solved_protocols_ssgen, solved_ports_ssgen, num_packets_sent_ssgen = ssgen_solver.solve_firewall()
end_time = datetime.now()
print("Small-Scale Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(blocked_ips + blocked_protocols + blocked_ports, solved_ips_ssgen + solved_protocols_ssgen + solved_ports_ssgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(blocked_ips + blocked_protocols + blocked_ports, solved_ips_ssgen + solved_protocols_ssgen + solved_ports_ssgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_ssgen)
print("Time used:", end_time - start_time)
print()

# Create ExGen Solver
# Reset lists in case they were previously changed
start_time = datetime.now()
exgen_solver = ExhaustiveGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall,
  population_size=1000,
  generations=2
)
solved_ips_exgen, solved_protocols_exgen, solved_ports_exgen, num_packets_sent_exgen = exgen_solver.solve_firewall()
end_time = datetime.now()
print("Exhaustive Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(blocked_ips + blocked_protocols + blocked_ports, solved_ips_exgen + solved_protocols_exgen + solved_ports_exgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(blocked_ips + blocked_protocols + blocked_ports, solved_ips_exgen + solved_protocols_exgen + solved_ports_exgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_exgen)
print("Time used:", end_time - start_time)
print()
