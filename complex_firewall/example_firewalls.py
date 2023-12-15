import dns
import random
from firewall import MockFirewall
from naive import NaiveSolver
from ssgen import SmallScaleGeneticSolver
from exgen import ExhaustiveGeneticSolver
from datetime import datetime

def random_selection(input_list):
  # make sure there is at least one that is approved
  num_elements_to_select = random.randint(1, len(input_list) - 1)
  selected_elements = random.sample(input_list, num_elements_to_select)
  return selected_elements

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

# Firewall 1 - 1 rule
list_of_possible_ips = dns.list_of_ips
list_of_possible_ports = list(range(1000))
list_of_possible_protocols = [
  "TCP", "UDP"
]
firewall_1 = MockFirewall()
firewall_1.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
# Create Naive Solver
start_time = datetime.now()
naive_solver = NaiveSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_1
)
rejected_packets, num_packets_sent = naive_solver.solve_firewall()
end_time = datetime.now()
print("Naive Algorithm")
print("---------------------------")
# We use naive as ground truth
print("Proportion of Rules Figured Out:", 1.0)
print("Jaccard Similarity:", 1.0)
print("Number of packets used:", num_packets_sent)
print("Time used:", end_time - start_time)
print()

# Create SSGen Solver
start_time = datetime.now()
ssgen_solver = SmallScaleGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_1,
  population_size=30,
  generations=10
)
rejected_packets_ssgen, num_packets_sent_ssgen = ssgen_solver.solve_firewall()
end_time = datetime.now()
print("Small-Scale Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_ssgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_ssgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_ssgen)
print("Time used:", end_time - start_time)
print()

# Create ExGen Solver
start_time = datetime.now()
exgen_solver = ExhaustiveGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_1,
  population_size=1,
  generations=3
)
rejected_packets_exgen, num_packets_sent_exgen = exgen_solver.solve_firewall()
end_time = datetime.now()
print("Exhaustive Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_exgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_exgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_exgen)
print("Time used:", end_time - start_time)
print()

# Firewall 2 - 2 rules
list_of_possible_ips = dns.list_of_ips
list_of_possible_ports = list(range(1000))
list_of_possible_protocols = [
  "TCP", "UDP"
]
firewall_2 = MockFirewall()
firewall_2.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
firewall_2.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
# Create Naive Solver
start_time = datetime.now()
naive_solver = NaiveSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_2
)
rejected_packets, num_packets_sent = naive_solver.solve_firewall()
end_time = datetime.now()
print("Naive Algorithm")
print("---------------------------")
# We use naive as ground truth
print("Proportion of Rules Figured Out:", 1.0)
print("Jaccard Similarity:", 1.0)
print("Number of packets used:", num_packets_sent)
print("Time used:", end_time - start_time)
print()

# Create SSGen Solver
start_time = datetime.now()
ssgen_solver = SmallScaleGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_2,
  population_size=30,
  generations=10
)
rejected_packets_ssgen, num_packets_sent_ssgen = ssgen_solver.solve_firewall()
end_time = datetime.now()
print("Small-Scale Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_ssgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_ssgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_ssgen)
print("Time used:", end_time - start_time)
print()

# Create ExGen Solver
start_time = datetime.now()
exgen_solver = ExhaustiveGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_2,
  population_size=1,
  generations=3
)
rejected_packets_exgen, num_packets_sent_exgen = exgen_solver.solve_firewall()
end_time = datetime.now()
print("Exhaustive Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_exgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_exgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_exgen)
print("Time used:", end_time - start_time)
print()

# Firewall 3 - 3 rules
list_of_possible_ips = dns.list_of_ips
list_of_possible_ports = list(range(1000))
list_of_possible_protocols = [
  "TCP", "UDP"
]
firewall_3 = MockFirewall()
firewall_3.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
firewall_3.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
firewall_3.add_rule(
  ips = random_selection(list_of_possible_ips),
  ports = random_selection(list_of_possible_ports),
  protocols = random_selection(list_of_possible_protocols),
  action='reject'
)
# Create Naive Solver
start_time = datetime.now()
naive_solver = NaiveSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_3
)
rejected_packets, num_packets_sent = naive_solver.solve_firewall()
end_time = datetime.now()
print("Naive Algorithm")
print("---------------------------")
# We use naive as ground truth
print("Proportion of Rules Figured Out:", 1.0)
print("Jaccard Similarity:", 1.0)
print("Number of packets used:", num_packets_sent)
print("Time used:", end_time - start_time)
print()

# Create SSGen Solver
start_time = datetime.now()
ssgen_solver = SmallScaleGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_3,
  population_size=30,
  generations=10
)
rejected_packets_ssgen, num_packets_sent_ssgen = ssgen_solver.solve_firewall()
end_time = datetime.now()
print("Small-Scale Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_ssgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_ssgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_ssgen)
print("Time used:", end_time - start_time)
print()

# Create ExGen Solver
start_time = datetime.now()
exgen_solver = ExhaustiveGeneticSolver(
  list_of_possible_ips.copy(), 
  list_of_possible_protocols.copy(), 
  list_of_possible_ports.copy(),
  firewall = firewall_3,
  population_size=1,
  generations=3
)
rejected_packets_exgen, num_packets_sent_exgen = exgen_solver.solve_firewall()
end_time = datetime.now()
print("Exhaustive Genetic Algorithm")
print("---------------------------")
# Calculate metrics
accuracy = rule_accuracy(rejected_packets, rejected_packets_exgen)
print("Proportion of Rules Figured Out:", accuracy)
similarity = jaccard_similarity(rejected_packets, rejected_packets_exgen)
print("Jaccard Similarity:", similarity)
# Check solution
print("Number of packets used:", num_packets_sent_exgen)
print("Time used:", end_time - start_time)
print()