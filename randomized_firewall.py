import dns
import firewall
import random
from naive import NaiveSolver
from genetic import GeneticSolver

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
blocked_ips = random_selection(list_of_possible_ips)
blocked_protocols = random_selection(list_of_possible_protocols)
blocked_ports = random_selection(list_of_possible_ports)
print("Number of blocked IPs:", len(blocked_ips))
print("Number of blocked protocols:", len(blocked_protocols))
print("Number of blocked ports:", len(blocked_ports))
print()
firewall = firewall.MockFirewall()
firewall.add_rule(
  ips = blocked_ips,
  ports = blocked_ports,
  protocols = blocked_protocols,
  action='reject'
)

list_of_possible_dests = dns.most_popular_sites
# Create Naive Solver
naive_solver = NaiveSolver(
  list_of_possible_dests, 
  list_of_possible_protocols, 
  list_of_possible_ports,
  firewall = firewall
)
solved_ips, solved_protocols, solved_ports, num_packets_sent = naive_solver.solve_firewall()
print("Naive Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(blocked_ips, solved_ips)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(blocked_ips, solved_ips)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent)
print()

# Create Genetic Solver
genetic_solver = GeneticSolver(
  list_of_possible_dests, 
  list_of_possible_protocols, 
  list_of_possible_ports,
  firewall = firewall,
  population_size=10000,
  generations=100
)
solved_ips, solved_protocols, solved_ports, num_packets_sent = genetic_solver.solve_firewall()
print("Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(blocked_ips, solved_ips)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(blocked_ips, solved_ips)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent)
print()

