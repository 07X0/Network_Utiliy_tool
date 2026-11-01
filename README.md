Network Utility Tool

A Python-Based Network Utility and Security Tool

Developed by Marwan Al Khateeb

Overview

Network Utility Tool is a Python-based application designed to perform common network diagnostic and analysis tasks.

The project provides two versions:

- CLI Version: A command-line interface for users who prefer terminal-based interaction.
- GUI Version: A graphical user interface built with Tkinter for easier interaction.

The project was developed to strengthen practical knowledge of Python programming, computer networking, and IT security.

Project Structure

Network_Utiliy_tool/
│
├── README_en.md
├── README_de.md
├── .gitignore
│
├── Console-Version/
│   ├── network_utility.py
│   └── README.md
│
└── GUI-Version/
    ├── network_utility_gui.py
    └── README.md

Features

CLI Version

- DNS Lookup
- Reverse DNS Lookup
- TCP Service Name Lookup
- TCP Port-to-Service Lookup
- TCP Port Scanning
- Local Host Information
- Network Host Scanning
- Network Interface Information
- Routing Table Lookup
- Network Packet Sniffing
- ARP Scanning

GUI Version

- Graphical interface built with Python and Tkinter
- DNS Lookup
- Reverse DNS Lookup
- TCP Service Lookup
- Port Scanning
- Local Network Information
- Network Host Scanning
- Console Output Display

Technologies Used

- Python
- Tkinter
- Socket Programming
- Scapy
- ThreadPoolExecutor
- IP Address Handling
- Network Protocols

Requirements

- Python 3
- Scapy
- Tkinter
- Administrator or root privileges for certain network operations

Install Scapy:

pip install scapy

Tkinter is included with many Python installations. On some Linux distributions, it must be installed separately.

Installation

Clone the repository:

git clone https://github.com/07X0/Network_Utiliy_tool.git

Navigate to the project directory:

cd Network_Utiliy_tool

Usage

CLI Version

python Console-Version/network_utility.py

GUI Version

python GUI-Version/network_utility_gui.py

Security Notice

This tool is intended for educational purposes, network diagnostics, and authorized security testing.

Only scan systems and networks that you own or have explicit permission to test.

Some features, such as packet sniffing and ARP scanning, may require elevated privileges.

Author

Marwan Al Khateeb

GitHub: https://github.com/07X0

Copyright

Copyright (c) 2026 Marwan Al Khateeb. All rights reserved.

Unauthorized redistribution or commercial use is not permitted without the author's permission.
