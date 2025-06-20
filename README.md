# SentinelLite AI Agent

Developed by **Abuzer**

An AI-based cybersecurity agent designed for IoT devices such as smart cameras and routers.

## Features

- Real-time packet monitoring with Scapy
- Threat signature detection (e.g., Mirai botnet ports, known malicious IPs)
- Anomaly detection with Isolation Forest ML model
- Automated policy actions including logging and IP blocking (optional)
- Simple GUI to monitor, control, and review alerts

## Requirements

- Python 3.7+
- Root privileges (for packet capture and firewall commands)

## Installation

```bash
git clone https://github.com/yourusername/sentinellite-ai-agent.git
cd sentinellite-ai-agent
pip install -r requirements.txt
