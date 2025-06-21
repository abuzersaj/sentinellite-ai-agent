

````markdown
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
git clone https://github.com/abuzersaj/sentinellite-ai-agent.git
cd sentinellite-ai-agent
pip install -r requirements.txt
````

## Usage

Run the tool with root/admin privileges to allow packet sniffing and firewall rules:

```bash
sudo python3 sentinellite_gui.py
```

* Enter the IP address of your IoT device (e.g., smart camera or router).
* Click **Start Monitoring** to begin.
* Enable IP blocking if you want automatic firewall blocking of detected threats.
* Stop monitoring by clicking **Stop Monitoring**.

## Notes

* IP blocking commands are simulated by default; be careful when enabling actual blocking.
* To fully stop the packet sniffing thread, you may need to restart the application.
* Logs are saved to `sentinellite_abuzer.log` in the project directory.
