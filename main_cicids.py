from cicids_loader import load_cicids, extract_cicids_features
from model import train_isolation_forest, get_anomaly_scores
from model_rf import prepare_supervised_data, train_random_forest, predict_with_rf, get_feature_importance
from detector import final_decision, final_decision_rf
from evaluation import evaluate_multi_attack, print_evaluation_report, generate_confusion_matrix

print("🔄 Loading CICIDS2017 dataset...")
df = load_cicids("data/CICIDS2017_ALL.csv")
df = df.sample(frac=0.2, random_state=42)
print(f"   Loaded {len(df):,} records")

print("🔧 Extracting features...")
features = extract_cicids_features(df)
print(f"   Generated features for {len(features)} ports")

print("\n" + "="*60)
print("           MODEL 1: ISOLATION FOREST")
print("="*60)
print("🤖 Training Isolation Forest model...")
if_model = train_isolation_forest(features, contamination=0.1, random_state=42)
if_scores, if_predictions = get_anomaly_scores(if_model, features)

print("🔍 Running Isolation Forest detection...")
if_decisions = {}
for port, row in features.iterrows():
    pred = if_predictions.loc[port]
    if_decisions[port] = final_decision(row, pred)

if_attack_counts = {}
for port, decision in if_decisions.items():
    if_attack_counts[decision] = if_attack_counts.get(decision, 0) + 1

print("\n📊 Isolation Forest Detection Summary:")
for attack_type, count in sorted(if_attack_counts.items(), key=lambda x: -x[1])[:5]:
    print(f"   {attack_type:30} : {count:5}")

print("\n🎯 Running Isolation Forest evaluation...")
if_results = evaluate_multi_attack(df, if_predictions, if_decisions)
print_evaluation_report(if_results)

print("\n" + "="*60)
print("           MODEL 2: RANDOM FOREST")
print("="*60)
print("🤖 Training Random Forest model...")
X, y = prepare_supervised_data(df)
print(f"   Features: {X.shape[1]}, Samples: {len(X):,}, Attack ratio: {y.mean():.1%}")
rf_model, rf_metrics, X_test, y_test = train_random_forest(X, y, n_estimators=100)

print("🔍 Running Random Forest detection...")
X_full = features.reset_index()

feature_cols = [
    'port', 'packets_per_sec', 'total_fwd_packets', 'duration',
    'total_bwd_packets', 'bytes_per_sec', 'syn_count', 'ack_count',
    'iat_mean', 'avg_pkt_size'
]
rf_predictions, rf_probabilities = predict_with_rf(rf_model, X_full[feature_cols])

rf_decisions = {}
for idx, port in enumerate(features.index):
    row = features.loc[port]
    rf_decisions[port] = final_decision_rf(row, rf_predictions[idx], rf_probabilities[idx])

rf_attack_counts = {}
for port, decision in rf_decisions.items():
    rf_attack_counts[decision] = rf_attack_counts.get(decision, 0) + 1

print("\n📊 Random Forest Detection Summary:")
for attack_type, count in sorted(rf_attack_counts.items(), key=lambda x: -x[1])[:5]:
    print(f"   {attack_type:30} : {count:5}")

print(f"\n✓ Accuracy: {rf_metrics['accuracy']:.2%}")
print("\n📋 Classification Report:")
print(rf_metrics['classification_report'])

print("\n🔑 Feature Importance:")
importance = get_feature_importance(rf_model, feature_cols)
for _, row in importance.iterrows():
    bar = "█" * int(row['importance'] * 50)
    print(f"   {row['feature']:20} {row['importance']:.3f} {bar}")

print("\n" + "="*60)
print("           MODEL COMPARISON SUMMARY")
print("="*60)

print(f"""
┌─────────────────────┬──────────────────────┬──────────────────────┐
│                     │  ISOLATION FOREST    │   RANDOM FOREST      │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Type                │ Unsupervised         │ Supervised           │
│ Labels Required     │ No                   │ Yes                  │
│ Precision           │ {if_results['overall']['precision']:18.1%} │ N/A (see accuracy)   │
│ Recall              │ {if_results['overall']['recall']:18.1%} │ N/A (see accuracy)   │
│ F1-Score            │ {if_results['overall']['f1']:18.1%} │ N/A (see accuracy)   │
│ Accuracy            │ N/A (unsupervised)   │ {rf_metrics['accuracy']:18.1%} │
│ Detections          │ {len([d for d in if_decisions.values() if d != 'Normal Traffic']):18} │ {len([d for d in rf_decisions.values() if d != 'Normal Traffic']):18} │
└─────────────────────┴──────────────────────┴──────────────────────┘
""")

print("\n✅ Analysis complete!")
print("\n💡 Conclusion:")
print("   • Isolation Forest: Detects unknown anomalies without labels")
print("   • Random Forest: Higher accuracy with labeled training data")
print("   • Best approach: Use both models for comprehensive detection!")

