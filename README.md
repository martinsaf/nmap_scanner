# nmap_scanner

## Description
This Python script utilizes nmap to perform targeted network scans, focusing on TCP and limited UDP port checks to identify and warn about potential vulnerabilities in network services. It is designed to quickly assess the security of common services like HTTP, FTP, and SMTP by analyzing service versions against known vulnerabilities.

## Prerequisites
Ensure you have the following installed:
- **Python**: Required to run the script.
- **Nmap**: Necessary for scanning functionalities.
- **python-nmap**: Install via pip with the command:
`pip install python-nmap`

## Installation
Clone the repository using the following command:
`git clone https://github.com/martinsaf/nmap_scanner.git`

## Usage
Run the script from the command line:
`python nmap_scanner.py`

Adjust the target IP in the script as necessary.
