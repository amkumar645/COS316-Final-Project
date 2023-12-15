## Setup
To set up the project, you can create a Python virtual environment. Within the environment, run: 
- pip install scapy

## Simple Firewall
To reproduce results regarding the Simple Firewall, cd into the simple_firewall directory. Within this directory, the files are:
- dns.py: Contains a list of 50 popular sites and uses a DNS Resolver to get their IP addresses
- firewall.py: Contains the implementation of the Simple Firewall
- naive.py: Contains the implementation of the Naive Algorithm for the Simple Firewall
- ssgen.py: Contains the implementation of the SSGen Algorithm for the Simple Firewall
- exgen.py: Contains the implementation of the ExGen Algorithm for the Simple Firewall
- randomized_firewall.py: Creates a Simple Firewall with randomized rules, then solves it with the Naive, SSGen, and ExGen algorithms and prints the results

To see the results, run: python randomized_firewall.py 

## Complex Firewall
To reproduce results regarding the Complex Firewall, cd into the complex_firewall directory. Within this directory, the files are:
- dns.py: Contains a list of 50 popular sites and uses a DNS Resolver to get their IP addresses
- firewall.py: Contains the implementation of the Complex Firewall
- naive.py: Contains the implementation of the Naive Algorithm for the Complex Firewall
- ssgen.py: Contains the implementation of the SSGen Algorithm for the Complex Firewall
- exgen.py: Contains the implementation of the ExGen Algorithm for the Complex Firewall
- example_firewalls.py: Creates 3 Complex Firewalls, one with 1 randomized rule, one with 2 randomized rules, and one with 3 randomized rules, and then solves it with the Naive, SSGen, and ExGen algorithms and prints the results

To see the results, run: python example_firewalls.py 
