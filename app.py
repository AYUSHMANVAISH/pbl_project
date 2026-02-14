from flask import Flask, render_template, jsonify, request
import random
import pandas as pd
import json
from cicids_loader import load_cicids, extract_cicids_features
from model import train_isolation_forest, get_anomaly_scores, load_model
from model_rf import prepare_supervised_data, train_random_forest, predict_with_rf, get_feature_importance, load_rf_model
from detector import final_decision, final_decision_rf
from evaluation import evaluate_multi_attack, generate_confusion_matrix
from rules import get_attack_types
from flow_detection import run_flow_level_analysis

app = Flask(__name__)

analysis_results = {
    'loaded': False,
    'mode': 'port',
    'df': None,
    'features': None,

    'if_predictions': None,
    'if_scores': None,
    'if_decisions': {},
    'if_evaluation': None,

    'rf_model': None,
    'rf_predictions': None,
    'rf_probabilities': None,
    'rf_decisions': {},
    'rf_metrics': None,

    'flow_results': None,
    'flow_predictions': None,
    'flow_probabilities': None,
    'flow_decisions': {},
    'port_stats': None,
    'malicious_ports': None,

    'predictions': None,
    'scores': None,
    'decisions': {},
    'evaluation': None
}

def run_analysis(sample_frac=0.1, mode='flow', aggregation_threshold=0.3):
    global analysis_results

    print(f"[*] Running analysis in {mode.upper()} mode...")
    print("Loading data...")
    df = load_cicids("data/CICIDS2017_ALL.csv")
    df = df.sample(frac=sample_frac, random_state=42)

    print("Extracting features...")
    features = extract_cicids_features(df)

    print("Loading/Training Isolation Forest...")
    if_model = load_model()
    if if_model is None:
        print("   Saved model not found. Training new model...")
        if_model = train_isolation_forest(features, contamination=0.1, random_state=42)
    else:
        print("   Loaded saved Isolation Forest model.")
        
    if_scores, if_predictions = get_anomaly_scores(if_model, features)

    print("Generating Isolation Forest decisions...")
    if_decisions = {}
    for port, row in features.iterrows():
        pred = if_predictions.loc[port]
        if_decisions[port] = final_decision(row, pred)

    print("Evaluating Isolation Forest...")
    if_evaluation = evaluate_multi_attack(df, if_predictions, if_decisions)

    print("Loading/Training Random Forest...")
    rf_model, rf_metrics = load_rf_model()
    
    if rf_model is None:
        print("   Saved model not found. Training new model...")
        X, y = prepare_supervised_data(df)
        rf_model, rf_metrics, X_test, y_test = train_random_forest(X, y, n_estimators=100)
    else:
        print(f"   Loaded saved Random Forest model (Accuracy: {rf_metrics['accuracy']:.2%})")

    results = {
        'loaded': True,
        'mode': mode,
        'df': df,
        'features': features,

        'if_predictions': if_predictions,
        'if_scores': if_scores,
        'if_decisions': if_decisions,
        'if_evaluation': if_evaluation,

        'rf_model': rf_model,
        'rf_metrics': rf_metrics,
    }

    if mode == 'flow':
        print(f"\n{'='*60}")
        print("FLOW-LEVEL DETECTION")
        print(f"{'='*60}")
        flow_results = run_flow_level_analysis(df, rf_model, aggregation_threshold)

        results.update({
            'flow_results': flow_results,
            'flow_predictions': flow_results['flow_predictions'],
            'flow_probabilities': flow_results['flow_probabilities'],
            'flow_decisions': flow_results['flow_decisions'],
            'port_stats': flow_results['port_stats'],
            'malicious_ports': flow_results['malicious_ports'],

            'predictions': flow_results['flow_predictions'],
            'decisions': flow_results['flow_decisions'],
        })

        print(f"\n[OK] Flow-level analysis complete!")
        print(f"  Total flows: {flow_results['total_flows']:,}")
        print(f"  Attack flows detected: {flow_results['attack_flows']:,} ({flow_results['attack_flows']/flow_results['total_flows']:.1%})")
        print(f"  Malicious ports: {flow_results['malicious_ports_count']:,} / {flow_results['total_ports']:,}")
        print(f"  RF Accuracy: {rf_metrics['accuracy']:.1%}")

    else:
        print("\nGenerating Random Forest predictions (port-level)...")
        X_full = features.reset_index()

        feature_cols = [
            'port', 'packets_per_sec', 'total_fwd_packets', 'duration',
            'total_bwd_packets', 'bytes_per_sec', 'syn_count', 'ack_count',
            'iat_mean', 'avg_pkt_size'
        ]
        rf_predictions, rf_probabilities = predict_with_rf(rf_model, X_full[feature_cols])

        print("Generating Random Forest decisions...")
        rf_decisions = {}
        for idx, port in enumerate(features.index):
            row = features.loc[port]
            rf_decisions[port] = final_decision_rf(row, rf_predictions[idx], rf_probabilities[idx])

        results.update({
            'rf_predictions': rf_predictions,
            'rf_probabilities': rf_probabilities,
            'rf_decisions': rf_decisions,

            'predictions': if_predictions,
            'scores': if_scores,
            'decisions': if_decisions,
            'evaluation': if_evaluation
        })

        print(f"[OK] Port-level analysis complete! IF Precision: {if_evaluation['overall']['precision']:.1%}, RF Accuracy: {rf_metrics['accuracy']:.1%}")

    analysis_results = results
    return analysis_results

@app.route('/')
def index():

    return render_template('index.html')

@app.route('/presentation')
def presentation():
    return render_template('presentation.html')

@app.route('/api/status')
def api_status():

    return jsonify({
        'loaded': analysis_results['loaded'],
        'records': len(analysis_results['df']) if analysis_results['loaded'] else 0,
        'ports': len(analysis_results['features']) if analysis_results['loaded'] else 0
    })

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json() or {}
    sample_frac = data.get('sample_frac', 0.1)
    mode = data.get('mode', 'flow')
    aggregation_threshold = data.get('aggregation_threshold', 0.3)

    try:
        run_analysis(sample_frac=sample_frac, mode=mode, aggregation_threshold=aggregation_threshold)
        return jsonify({'success': True, 'message': f'{mode.capitalize()}-level analysis complete'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    mode = analysis_results.get('mode', 'port')

    if mode == 'flow':
        flow_results = analysis_results['flow_results']
        port_stats = analysis_results['port_stats']
        malicious_ports = analysis_results['malicious_ports']
        rf_metrics = analysis_results['rf_metrics']
        df = analysis_results['df']
        flow_preds = analysis_results.get('flow_predictions')

        threat_counts = {k: int(v) for k, v in malicious_ports['threat_level'].value_counts().to_dict().items()} if len(malicious_ports) > 0 else {}

        total_flows = int(flow_results['total_flows'])
        attack_flows = int(flow_results['attack_flows'])

        cm = rf_metrics['confusion_matrix']
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        per_attack = {}
        if flow_preds is not None:
            df_eval = df.copy()
            df_eval['predicted'] = flow_preds
            attack_df = df_eval[df_eval['label'].str.upper() != 'BENIGN']
            for label, group in attack_df.groupby('label'):
                total = len(group)
                detected = int(group['predicted'].sum())
                per_attack[label] = {
                    'total': int(total),
                    'detected': detected,
                    'detection_rate': round(detected / total * 100, 1) if total > 0 else 0
                }

        return jsonify({
            'mode': 'flow',
            'total_flows': total_flows,
            'attack_flows': attack_flows,
            'benign_flows': total_flows - attack_flows,
            'total_ports': int(flow_results['total_ports']),
            'malicious_ports': int(flow_results['malicious_ports_count']),
            'threat_counts': threat_counts,
            'aggregation_threshold': float(flow_results['aggregation_threshold']),
            'metrics': {
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'accuracy': rf_metrics['accuracy']
            },
            'confusion_matrix': {
                'true_positive': tp,
                'false_positive': fp,
                'true_negative': tn,
                'false_negative': fn
            },
            'per_attack': per_attack
        })
    else:
        if_decisions = analysis_results['if_decisions']
        if_evaluation = analysis_results['if_evaluation']

        attack_counts = {}
        for decision in if_decisions.values():
            attack_counts[decision] = attack_counts.get(decision, 0) + 1

        overall = if_evaluation['overall']

        if_cm = {
            'true_positive': overall['true_positives'],
            'false_positive': overall['false_positives'],
            'true_negative': len(analysis_results['features']) - overall['true_positives'] - overall['false_positives'] - overall['false_negatives'],
            'false_negative': overall['false_negatives']
        }

        return jsonify({
            'mode': 'port',
            'total_ports': len(analysis_results['features']),
            'total_records': len(analysis_results['df']),
            'attack_counts': attack_counts,
            'metrics': {
                'precision': overall['precision'],
                'recall': overall['recall'],
                'f1': overall['f1']
            },
            'per_attack': if_evaluation['per_attack'],
            'confusion_matrix': if_cm,
            'model': 'Isolation Forest'
        })

@app.route('/api/anomalies')
def api_anomalies():
    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    limit = request.args.get('limit', 50, type=int)
    mode = analysis_results.get('mode', 'port')

    if mode == 'flow':
        port_stats = analysis_results.get('port_stats')
        if port_stats is None or port_stats.empty:
            return jsonify([])

        top = port_stats.nlargest(limit, 'max_probability')

        anomalies = []
        for _, row in top.iterrows():
            anomalies.append({
                'port': int(row['port']),
                'score': round(float(row['max_probability']), 4),
                'decision': row['threat_level'],
                'request_count': int(row['total_flows']),
                'request_rate': round(float(row['attack_ratio'] * 100), 2),
                'avg_duration': round(float(row['avg_probability']), 4)
            })
    else:
        decisions = analysis_results['decisions']
        features = analysis_results['features']
        scores = analysis_results['scores']
        top_ports = scores.sort_values(ascending=False).head(limit)

        anomalies = []
        for port, score in top_ports.items():
            row = features.loc[port]
            req_rate = float(row.get('request_rate', 0))
            if not pd.isna(req_rate) and req_rate != float('inf'):
                req_rate_safe = round(req_rate, 2)
            else:
                req_rate_safe = 999999.99

            anomalies.append({
                'port': int(port),
                'score': round(float(score), 4),
                'decision': decisions.get(port, 'Unknown'),
                'request_count': int(row.get('request_count', 0)),
                'request_rate': req_rate_safe,
                'avg_duration': round(float(row.get('avg_duration', 0)), 2)
            })

    return jsonify(anomalies)

@app.route('/api/live')
def api_live():
    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    mode = analysis_results.get('mode', 'port')

    if mode == 'flow':
        df = analysis_results['df']
        flow_preds = analysis_results.get('flow_predictions')
        flow_probs = analysis_results.get('flow_probabilities')
        flow_decisions = analysis_results.get('flow_decisions', {})

        if flow_preds is None:
            return jsonify({'error': 'No flow data available'}), 400

        idx = random.randint(0, len(df) - 1)
        row = df.iloc[idx]
        pred = int(flow_preds[idx])
        prob = float(flow_probs[idx])
        decision = flow_decisions.get(idx, 'Unknown')

        return jsonify({
            'port': int(row['port']),
            'score': round(prob, 4),
            'decision': decision,
            'is_attack': pred == 1,
            'packets_per_sec': round(float(row.get('packets_per_sec', 0)), 2),
            'bytes_per_sec': round(float(row.get('bytes_per_sec', 0)), 2),
            'duration': round(float(row.get('duration', 0)), 2),
            'label': str(row.get('label', 'Unknown')),
            'timestamp': pd.Timestamp.now().isoformat()
        })
    else:
        decisions = analysis_results['decisions']
        features = analysis_results['features']
        scores = analysis_results['scores']

        ports = list(features.index)
        port = random.choice(ports)
        row = features.loc[port]
        score = float(scores.loc[port])
        decision = decisions.get(port, 'Unknown')

        return jsonify({
            'port': int(port),
            'score': round(score, 4),
            'decision': decision,
            'is_attack': decision != 'Normal Traffic',
            'packets_per_sec': round(float(row.get('packets_per_sec', 0)), 2),
            'bytes_per_sec': round(float(row.get('bytes_per_sec', 0)), 2),
            'duration': round(float(row.get('duration', 0)), 2),
            'timestamp': pd.Timestamp.now().isoformat()
        })

@app.route('/api/scores')
def api_scores():

    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    scores = analysis_results['scores']

    bins = pd.cut(scores, bins=20)
    distribution = bins.value_counts().sort_index()

    return jsonify({
        'labels': [str(interval) for interval in distribution.index],
        'values': distribution.values.tolist(),
        'min': float(scores.min()),
        'max': float(scores.max()),
        'mean': float(scores.mean())
    })

@app.route('/api/model/rf')
def api_rf_metrics():

    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    rf_metrics = analysis_results['rf_metrics']
    rf_decisions = analysis_results['rf_decisions']

    attack_counts = {}
    for decision in rf_decisions.values():
        attack_counts[decision] = attack_counts.get(decision, 0) + 1

    features_list = [
        'port', 'packets_per_sec', 'total_fwd_packets', 'duration',
        'total_bwd_packets', 'bytes_per_sec', 'syn_count', 'ack_count',
        'iat_mean', 'avg_pkt_size'
    ]
    importance = get_feature_importance(analysis_results['rf_model'], features_list)

    return jsonify({
        'accuracy': rf_metrics['accuracy'],
        'classification_report': rf_metrics['classification_report'],
        'confusion_matrix': rf_metrics['confusion_matrix'],
        'attack_counts': attack_counts,
        'feature_importance': importance.to_dict('records')
    })

@app.route('/api/model/compare')
def api_compare_models():

    if not analysis_results['loaded']:
        return jsonify({'error': 'No analysis loaded'}), 400

    if_eval = analysis_results['if_evaluation']
    rf_metrics = analysis_results['rf_metrics']

    return jsonify({
        'isolation_forest': {
            'type': 'Unsupervised',
            'precision': if_eval['overall']['precision'],
            'recall': if_eval['overall']['recall'],
            'f1': if_eval['overall']['f1'],
            'total_detections': len([d for d in analysis_results['if_decisions'].values() if d != 'Normal Traffic'])
        },
        'random_forest': {
            'type': 'Supervised',
            'accuracy': rf_metrics['accuracy'],
            'confusion_matrix': rf_metrics['confusion_matrix'],
            'total_detections': len([d for d in analysis_results['rf_decisions'].values() if d != 'Normal Traffic'])
        }
    })

if __name__ == '__main__':
    print("[*] Starting AnomXShield Dashboard...")
    print("    Server ready! Open http://localhost:5000")
    print("    Click 'Run Analysis' in the web UI to start detection.")
    app.run(debug=True, port=5000)

