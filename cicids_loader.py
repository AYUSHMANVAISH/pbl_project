import pandas as pd

def load_cicids(path):
    df = pd.read_csv(path)

    df.columns = df.columns.str.strip()

    required = [
        'Destination Port',
        'Flow Packets/s',
        'Total Fwd Packets',
        'Flow Duration',
        'Total Backward Packets',
        'Flow Bytes/s',
        'SYN Flag Count',
        'ACK Flag Count',
        'Flow IAT Mean',
        'Average Packet Size',
        'Label'
    ]

    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[required]

    df = df.rename(columns={
        'Destination Port': 'port',
        'Flow Packets/s': 'packets_per_sec',
        'Total Fwd Packets': 'total_fwd_packets',
        'Flow Duration': 'duration',
        'Total Backward Packets': 'total_bwd_packets',
        'Flow Bytes/s': 'bytes_per_sec',
        'SYN Flag Count': 'syn_count',
        'ACK Flag Count': 'ack_count',
        'Flow IAT Mean': 'iat_mean',
        'Average Packet Size': 'avg_pkt_size',
        'Label': 'label'
    })

    return df

def extract_cicids_features(df):
    import numpy as np

    features = df.groupby('port').agg(
        packets_per_sec=('packets_per_sec', 'mean'),
        total_fwd_packets=('total_fwd_packets', 'sum'),
        duration=('duration', 'mean'),
        total_bwd_packets=('total_bwd_packets', 'sum'),
        bytes_per_sec=('bytes_per_sec', 'mean'),
        syn_count=('syn_count', 'sum'),
        ack_count=('ack_count', 'sum'),
        iat_mean=('iat_mean', 'mean'),
        avg_pkt_size=('avg_pkt_size', 'mean')
    )

    features = features.fillna(0)
    features = features.replace([np.inf, -np.inf], 0)

    return features
