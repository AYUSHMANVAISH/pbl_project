import pandas as pd
from model_rf import predict_with_rf
from detector import final_decision_rf
from rules import cicids_rule_detection

def aggregate_flows_to_ports(df, flow_predictions, flow_probabilities, threshold=0.3):
    df_temp = df.copy()
    df_temp['prediction'] = flow_predictions
    df_temp['probability'] = flow_probabilities

    port_stats = df_temp.groupby('port').agg({
        'prediction': ['sum', 'count', 'mean'],
        'probability': ['mean', 'max']
    }).reset_index()

    port_stats.columns = ['port', 'attack_flows', 'total_flows', 'attack_ratio',
                          'avg_probability', 'max_probability']

    port_stats['is_malicious'] = port_stats['attack_ratio'] >= threshold

    def get_threat_level(row):
        if not row['is_malicious']:
            return 'Normal Traffic'
        elif row['attack_ratio'] >= 0.8:
            return 'Critical Threat'
        elif row['attack_ratio'] >= 0.5:
            return 'High Threat'
        elif row['attack_ratio'] >= 0.3:
            return 'Medium Threat'
        else:
            return 'Low Threat'

    port_stats['threat_level'] = port_stats.apply(get_threat_level, axis=1)

    return port_stats

def run_flow_level_analysis(df, rf_model, aggregation_threshold=0.3):
    from model_rf import prepare_supervised_data

    print(f"  Running flow-level detection...")

    X_flows, y_true = prepare_supervised_data(df)

    flow_predictions, flow_probabilities = predict_with_rf(rf_model, X_flows)

    print(f"  Aggregating flows to ports (threshold={aggregation_threshold})...")

    port_stats = aggregate_flows_to_ports(df, flow_predictions, flow_probabilities,
                                          threshold=aggregation_threshold)

    flow_decisions = {}
    for idx, (pred, prob) in enumerate(zip(flow_predictions, flow_probabilities)):
        if pred == 1:
            if prob > 0.8:
                flow_decisions[idx] = "High Confidence Attack"
            elif prob > 0.5:
                flow_decisions[idx] = "Medium Confidence Attack"
            else:
                flow_decisions[idx] = "Low Confidence Attack"
        elif prob > 0.3:
            flow_decisions[idx] = "Suspected Anomalous Traffic"
        else:
            flow_decisions[idx] = "Normal Traffic"

    malicious_ports = port_stats[port_stats['is_malicious']]

    results = {
        'mode': 'flow',
        'flow_predictions': flow_predictions,
        'flow_probabilities': flow_probabilities,
        'flow_decisions': flow_decisions,
        'port_stats': port_stats,
        'malicious_ports': malicious_ports,
        'total_flows': len(df),
        'attack_flows': (flow_predictions == 1).sum(),
        'total_ports': len(port_stats),
        'malicious_ports_count': len(malicious_ports),
        'aggregation_threshold': aggregation_threshold
    }

    return results
