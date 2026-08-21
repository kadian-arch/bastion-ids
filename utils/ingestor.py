import pandas as pd

class BastionIngestor:
    def __init__(self):
        # These are the standard features the models were trained on
        self.feature_names = [
            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 
            'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 
            'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 
            'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
            'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 
            'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
            'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 
            'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm', 
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
        ]

    def stream_csv(self, file_path, chunk_size=1):
        """
        Robust streaming: Assigns standard headers to raw files 
        to ensure the engine always receives a consistent format.
        """
        # We use names=self.feature_names to handle files that lack headers
        return pd.read_csv(
            file_path, 
            chunksize=chunk_size, 
            names=self.feature_names, 
            header=None,
            low_memory=False
        )