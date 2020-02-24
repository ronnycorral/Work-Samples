#Automate Docker Container Security Scans Using Clair
###Ron Corral

I automated security scans for the docker containers in a registry and reports on the results.


- clair.yml - Ansible playbook that launches an EC2 instance with Clair and PostgrSQL installed then runs a generatereport.py that automates security scans.
- generatereport.py - Gets a list of containers from the registry, scans them using Clair and parses the json output into a report
