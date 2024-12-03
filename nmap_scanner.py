# -*- coding: utf-8 -*-
import nmap  # Import the nmap library

# Create an instance of the nmap scanner
nm = nmap.PortScanner()

# Define the target for the scan
target = '192.168.1.1'

# Execute a TCP port scan with modified service version detection and timing
nm.scan(target, '80,443,21,25,110,143', '-v -sS -sV --version-intensity 5 -T4')

# Print the TCP scan results
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
            
            # Generic vulnerability checks based on common services
            if 'http' in service_info['name']:
                version = service_info['version']
                product = service_info['product'].lower()
                if 'apache' in product and version < "2.4.46":
                    print(f"WARNING: Apache version {version} might be vulnerable. Consider upgrading.")
                elif 'nginx' in product and version < "1.18.0":
                    print(f"WARNING: Nginx version {version} might be vulnerable. Consider upgrading.")
            elif 'ftp' in service_info['name']:
                version = service_info['version']
                if 'vsftpd' in service_info['product'] and version < "3.0.3":
                    print(f"WARNING: vsFTPd version {version} might be vulnerable. Consider upgrading.")
            elif 'smtp' in service_info['name']:
                version = service_info['version']
                if 'exim' in service_info['product'] and version < "4.94.2":
                    print(f"WARNING: Exim SMTP version {version} might be vulnerable. Consider upgrading.")
