# Domain Analysis Tool

## Introduction
This tool is designed for in-depth analysis of domains and websites. It provides valuable insights such as associated IP addresses, open ports, content management systems (CMS), SSL certificates, and more, which can be crucial for security assessments and web development.

## Features
- Discovering IP addresses associated with a domain.
- Detecting load balancers.
- Scanning for open ports.
- Finding subdomains.
- Identifying the CMS used by a website.
- Checking SSL certificate details.
- Detecting Web Application Firewalls (WAF).
- Extracting email addresses from web pages.
- Retrieving WHOIS information.
- Conducting Nmap scans.

## Prerequisites
Before you can use this tool, ensure that you have Python installed on your system. Additionally, you will need the following Python libraries:
- dnspython: For performing DNS queries.
- requests: For making HTTP requests.
- beautifulsoup4: For parsing HTML and extracting information.
- python-whois: For retrieving WHOIS information.
- python-nmap: For interacting with Nmap network scanner.

Python can be installed from python.org, and the libraries can be installed using pip, the Python package installer.

## Installation
To install the required dependencies, execute the following command in your terminal:

`bash
pip install dnspython requests beautifulsoup4 python-whois python-nmap
