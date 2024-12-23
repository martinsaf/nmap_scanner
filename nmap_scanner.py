# -*- coding: utf-8 -*-
import nmap  # Import the nmap library

# Create an instance of the nmap scanner
nm = nmap.PortScanner()

# Define the target for the scan
target = '192.168.1.1'

# Arguments for the main TCP scan
arguments = '-v -sS -sV --version-intensity 5 -T4 --script auth,vuln,exploit,discovery --script-args=safe --defeat-rst-ratelimit'
nm.scan(target, '80,443,21,25,110,143', arguments=arguments)

# Save and print results from the main TCP scan
print("\nTCP Scan Results:")
for host in nm.all_hosts():
    print(f'Host : {host} ({nm[host].hostname()})')
    print(f'State : {nm[host].state()}')
    for proto in nm[host].all_protocols():
        print('----------')
        print(f'Protocol : {proto}')
        lport = nm[host][proto].keys()
        for port in sorted(lport):
            service_info = nm[host][proto][port]
            print(f'port : {port}\tstate : {service_info["state"]}')
            if service_info.get('product'):
                print(f'Service : {service_info["name"]}, Product : {service_info["product"]}, Version : {service_info["version"]}')

# You may remove or comment out the following lines if you don't want to perform additional scans
# Perform an ACK scan to detect firewall filters
nm.scan(target, '80,443,21,25,110,143', arguments='-sA')

# Perform a ping scan to see which hosts are up
nm.scan(target, arguments='-sn')

# Optional: Display command line used for scans and scan info after significant scans only
if nm.scaninfo():
    print(nm.command_line())  # Shows the command line Nmap is using
    print(nm.scaninfo())      # Shows the information about the scan
print(nm.all_hosts())     # Show all host(s) found
