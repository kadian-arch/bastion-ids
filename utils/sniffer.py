from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import json
import os
import datetime

class BastionSniffer:
    def __init__(self, engine):
        self.engine = engine
        self.log_file = "alerts.json"
        # EXACT FEATURE SET FROM YOUR INGESTOR
        self.feature_names = [
            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 
            'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 
            'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 
            'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
            'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 
            'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
            'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 
            'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
        ]

    def packet_callback(self, pkt):
        if pkt.haslayer(IP):
            # Create a zeroed base dictionary for all features
            data = {feat: [0] for feat in self.feature_names}
            
            # Map Live Packet data
            data['srcip'] = [pkt[IP].src]
            data['dstip'] = [pkt[IP].dst]
            data['proto'] = [pkt[IP].proto]
            data['sttl'] = [pkt[IP].ttl]
            data['sbytes'] = [len(pkt)]
            data['Stime'] = [datetime.datetime.now().timestamp()]
            
            if pkt.haslayer(TCP):
                data['sport'] = [pkt[TCP].sport]
                data['dsport'] = [pkt[TCP].dport]
                data['state'] = ['CON']
            elif pkt.haslayer(UDP):
                data['sport'] = [pkt[UDP].sport]
                data['dsport'] = [pkt[UDP].dport]
                data['state'] = ['INT']

            # Analyze through the 3-Layer Hybrid Engine
            df = pd.DataFrame(data)
            verdict, confidence, source = self.engine.analyze_flow(df)

            # Log EVERY detection that isn't normal (Wireshark-style)
            self._write_to_log(verdict, confidence, source, pkt[IP].src)

    def _write_to_log(self, verdict, conf, source, ip):
        log_entry = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "verdict": verdict,
            "confidence": f"{round(conf * 100, 2)}%",
            "source": source,
            "origin": ip
        }
        
        # Thread-safe log append
        alerts = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    alerts = json.load(f)
            except: pass
        
        alerts.append(log_entry)
        with open(self.log_file, 'w') as f:
            json.dump(alerts[-200:], f, indent=4) # Keep last 200 for UI scrolling

    def start_live_capture(self, interface="eth0"):
        print(f"BASTION_CORE: Sniffer engaged on {interface}")
        sniff(iface=interface, prn=self.packet_callback, store=0)