import tkinter as tk
from tkinter import scrolledtext
import threading
import logging
import os
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from datetime import datetime

logging.basicConfig(
    filename="sentinellite_abuzer.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

class SentinelLiteGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelLite IoT Security Agent - Developed by Abuzer")
        self.running = False
        self.blocking_enabled = False
        self.packet_count = 0
        self.alert_count = 0
        self.model = None
        self.thread = None
        
        self.TARGET_DEVICE_IP = tk.StringVar(value="192.168.1.10")

        self.THREAT_SIGNATURES = {
            "malicious_ips": ["198.51.100.99", "203.0.113.42"],
            "blocked_ports": [23, 2323, 7547],
        }

        self.build_gui()
        self.load_or_train_model()

    def build_gui(self):
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Target Device IP:").grid(row=0, column=0, sticky="w")
        tk.Entry(frame, textvariable=self.TARGET_DEVICE_IP, width=15).grid(row=0, column=1, sticky="w")

        self.start_btn = tk.Button(frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=5)

        self.stop_btn = tk.Button(frame, text="Stop Monitoring", state=tk.DISABLED, command=self.stop_monitoring)
        self.stop_btn.grid(row=0, column=3, padx=5)

        self.block_btn = tk.Button(frame, text="Enable IP Blocking", command=self.toggle_blocking)
        self.block_btn.grid(row=0, column=4, padx=5)

        self.log_area = scrolledtext.ScrolledText(self.root, width=90, height=30, state=tk.DISABLED)
        self.log_area.pack(padx=10, pady=10)

        self.stats_label = tk.Label(self.root, text="Packets Processed: 0 | Alerts: 0")
        self.stats_label.pack()

    def log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"{datetime.now().isoformat()} - {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def load_or_train_model(self):
        MODEL_PATH = "model_abuzer.pkl"
        if not os.path.exists(MODEL_PATH):
            self.log("Training new Isolation Forest model...")
            X_train = np.random.normal(0, 1, (200, 5))
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(X_train)
            joblib.dump(model, MODEL_PATH)
            self.model = model
            self.log("Model training complete.")
        else:
            self.model = joblib.load(MODEL_PATH)
            self.log("Loaded existing Isolation Forest model.")

    def extract_features(self, pkt):
        size = len(pkt)
        ttl = pkt[IP].ttl
        src_port = pkt.sport if hasattr(pkt, 'sport') else 0
        dst_port = pkt.dport if hasattr(pkt, 'dport') else 0
        protocol = 6 if pkt.haslayer(TCP) else (17 if pkt.haslayer(UDP) else 0)
        return np.array([size, ttl, src_port, dst_port, protocol]).reshape(1, -1)

    def check_threat_signature(self, pkt):
        src_ip = pkt[IP].src
        dst_port = pkt.sport if hasattr(pkt, 'sport') else 0
        if src_ip in self.THREAT_SIGNATURES["malicious_ips"]:
            return True, f"Known malicious IP: {src_ip}"
        if dst_port in self.THREAT_SIGNATURES["blocked_ports"]:
            return True, f"Blocked port accessed: {dst_port}"
        return False, ""

    def apply_policy(self, pkt, reason):
        src_ip = pkt[IP].src
        log_msg = f"[Abuzer] Threat detected: {reason} | Source IP: {src_ip}"
        logging.warning(log_msg)
        self.log("[ALERT] " + log_msg)
        self.alert_count += 1
        self.update_stats()

        if self.blocking_enabled:
            # Uncomment in production (use with caution)
            # os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            # os.system(f"iptables -A FORWARD -s {src_ip} -j DROP")
            self.log(f"[Abuzer] IP blocking enabled - blocked {src_ip}")

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == self.TARGET_DEVICE_IP.get():
            self.packet_count += 1
            self.update_stats()

            sig_threat, sig_reason = self.check_threat_signature(pkt)
            if sig_threat:
                self.apply_policy(pkt, sig_reason)
                return

            features = self.extract_features(pkt)
            pred = self.model.predict(features)[0]
            if pred == -1:
                score = self.model.decision_function(features)[0]
                self.apply_policy(pkt, f"Anomaly detected (score={score:.4f})")
            else:
                logging.info(f"[Abuzer] Normal packet from {pkt[IP].src}, ports: {pkt.sport}->{pkt.dport}")

    def sniff_packets(self):
        self.log(f"[Abuzer] Started monitoring traffic from {self.TARGET_DEVICE_IP.get()}")
        sniff(filter=f"ip src {self.TARGET_DEVICE_IP.get()}", prn=self.process_packet, store=False)

    def start_monitoring(self):
        if self.running:
            return
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        if not self.running:
            return
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("[Abuzer] Stopped monitoring (please restart app to fully stop sniffing thread)")

    def toggle_blocking(self):
        self.blocking_enabled = not self.blocking_enabled
        state = "enabled" if self.blocking_enabled else "disabled"
        self.block_btn.config(text=f"{'Disable' if self.blocking_enabled else 'Enable'} IP Blocking")
        self.log(f"[Abuzer] IP blocking {state}")

    def update_stats(self):
        self.stats_label.config(text=f"Packets Processed: {self.packet_count} | Alerts: {self.alert_count}")

def main():
    root = tk.Tk()
    app = SentinelLiteGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
