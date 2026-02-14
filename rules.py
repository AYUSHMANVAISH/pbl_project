THRESHOLDS = {
    'ddos': {
        'request_rate': 500,
        'request_count': 2500
    },
    'portscan': {
        'unique_ports': 50,
        'request_rate': 300
    },
    'brute_force': {
        'request_count': 50,
        'avg_duration': 100
    },
    'high_volume': {
        'request_count': 1000
    }
}

def detect_ddos(row):

    if row.get('request_rate', 0) > THRESHOLDS['ddos']['request_rate']:
        return True
    if row.get('request_count', 0) > THRESHOLDS['ddos']['request_count']:
        return True
    return False

def detect_portscan(row):

    if (row.get('request_rate', 0) > THRESHOLDS['portscan']['request_rate'] and
        row.get('request_count', 0) < THRESHOLDS['ddos']['request_count']):
        return True
    return False

def detect_brute_force(row):

    if (row.get('request_count', 0) > THRESHOLDS['brute_force']['request_count'] and
        row.get('avg_duration', float('inf')) < THRESHOLDS['brute_force']['avg_duration']):
        return True
    return False

def detect_high_volume(row):

    if row.get('request_count', 0) > THRESHOLDS['high_volume']['request_count']:
        return True
    return False

def cicids_rule_detection(row):

    if detect_ddos(row):
        return "DDoS Attack"

    if detect_portscan(row):
        return "PortScan Attack"

    if detect_brute_force(row):
        return "Brute Force Attack"

    if detect_high_volume(row):
        return "High Volume Traffic"

    return "Normal"

def get_attack_types():
    return [
        "DDoS Attack",
        "PortScan Attack",
        "Brute Force Attack",
        "High Volume Traffic",
        "High Confidence Attack",
        "Medium Confidence Attack",
        "Low Confidence Attack",
        "Suspected Anomalous Traffic",
        "Unknown Anomalous Traffic",
        "Normal Traffic"
    ]

