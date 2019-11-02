### Objective: Perform reverse DNS lookups of all virtual-addresses and associated pool member addresses. 
###
### Requirements: 
1. perl on local host
### 
### Usage: ./VIPandNodeDig.pl bigip.conf
#### Details:
  
  For each virtual server and associated pool (by way of iRule or default pool), perform DNS lookup of each virtual-address, and pool member address.
  
  Results will be grouped by virtual address and output to a CSV file.
	
  Useful for determining fqdn of virtual-addresses and associated pool member addresses in order to identify application owner

  TODO:
  
    1. collect the VS and Pool description and include in the output
    
    2. read a GTM config file to perform reverse lookups on GTM server VS addresses.
