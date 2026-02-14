import pandas as pd
from collections import defaultdict

def calculate_metrics(y_true, y_pred):

    y_true = set(y_true)
    y_pred = set(y_pred)

    tp = len(y_pred & y_true)
    fp = len(y_pred - y_true)
    fn = len(y_true - y_pred)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn
    }

def get_attack_labels(df, attack_type):

    mask = df['label'].str.contains(attack_type, case=False, na=False)
    return set(df[mask]['port'].unique())

def evaluate_multi_attack(df, predictions, decisions):

    results = {}

    attack_types = {
        'DDoS': 'DDoS',
        'PortScan': 'PortScan',
        'DoS': 'DoS',
        'Bot': 'Bot',
        'Infiltration': 'Infiltration',
        'Web Attack': 'Web Attack',
        'Brute Force': 'Brute Force'
    }

    all_attack_ports = set()
    benign_mask = df['label'].str.upper() == 'BENIGN'
    attack_mask = ~benign_mask
    all_attack_ports = set(df[attack_mask]['port'].unique())

    predicted_anomaly_ports = set(predictions[predictions == -1].index)

    results['overall'] = calculate_metrics(all_attack_ports, predicted_anomaly_ports)
    results['overall']['total_attacks'] = len(all_attack_ports)
    results['overall']['total_predicted'] = len(predicted_anomaly_ports)

    results['per_attack'] = {}
    for name, pattern in attack_types.items():
        true_ports = get_attack_labels(df, pattern)
        if len(true_ports) > 0:
            detected = predicted_anomaly_ports & true_ports
            results['per_attack'][name] = {
                'total': len(true_ports),
                'detected': len(detected),
                'detection_rate': len(detected) / len(true_ports) * 100
            }

    return results

def print_evaluation_report(results):

    print("\n" + "="*60)
    print("           EVALUATION REPORT")
    print("="*60)

    overall = results['overall']
    print(f"\n📊 OVERALL METRICS")
    print(f"   Precision:  {overall['precision']:.2%}")
    print(f"   Recall:     {overall['recall']:.2%}")
    print(f"   F1-Score:   {overall['f1']:.2%}")
    print(f"\n   True Positives:  {overall['true_positives']}")
    print(f"   False Positives: {overall['false_positives']}")
    print(f"   False Negatives: {overall['false_negatives']}")

    if results.get('per_attack'):
        print(f"\n📈 PER-ATTACK DETECTION RATES")
        print("-" * 40)
        for attack, metrics in results['per_attack'].items():
            bar = "█" * int(metrics['detection_rate'] / 5)
            print(f"   {attack:15} {metrics['detection_rate']:6.1f}% {bar}")
            print(f"                    ({metrics['detected']}/{metrics['total']} detected)")

    print("\n" + "="*60)

def generate_confusion_matrix(df, predictions):

    benign_ports = set(df[df['label'].str.upper() == 'BENIGN']['port'].unique())
    attack_ports = set(df[df['label'].str.upper() != 'BENIGN']['port'].unique())

    pred_normal = set(predictions[predictions == 1].index)
    pred_anomaly = set(predictions[predictions == -1].index)

    return {
        'true_positive': len(pred_anomaly & attack_ports),
        'true_negative': len(pred_normal & benign_ports),
        'false_positive': len(pred_anomaly & benign_ports),
        'false_negative': len(pred_normal & attack_ports)
    }
