from cicids_loader import load_cicids, extract_cicids_features
from model import train_isolation_forest, get_anomaly_scores
from model_rf import prepare_supervised_data, train_random_forest, print_rf_report, get_feature_importance
from evaluation import evaluate_multi_attack, print_evaluation_report
import pandas as pd

print("="*70)
print("       ANOMXSHIELD - MODEL COMPARISON")
print("       Isolation Forest vs Random Forest")
print("="*70)

print("\n[1/5] Loading CICIDS2017 dataset...")
df = load_cicids("data/CICIDS2017_ALL.csv")
df = df.sample(frac=0.2, random_state=42)
print(f"      Loaded {len(df):,} records")

print("\n" + "-"*70)
print("MODEL 1: ISOLATION FOREST (Unsupervised)")
print("-"*70)

print("\n[2/5] Training Isolation Forest...")
features = extract_cicids_features(df)
if_model = train_isolation_forest(features, contamination=0.1, random_state=42)
if_scores, if_predictions = get_anomaly_scores(if_model, features)

if_results = evaluate_multi_attack(df, if_predictions, {})
print_evaluation_report(if_results)

print("\n" + "-"*70)
print("MODEL 2: RANDOM FOREST (Supervised)")
print("-"*70)

print("\n[3/5] Preparing supervised data...")
X, y = prepare_supervised_data(df)
print(f"      Features: {X.shape[1]}, Samples: {len(X):,}")
print(f"      Attack ratio: {y.mean():.1%}")

print("\n[4/5] Training Random Forest...")
rf_model, rf_metrics, X_test, y_test = train_random_forest(X, y, n_estimators=100)
print_rf_report(rf_metrics)

print("\n[5/5] Feature Importance:")
importance = get_feature_importance(rf_model, X.columns.tolist())
for _, row in importance.iterrows():
    bar = "#" * int(row['importance'] * 50)
    print(f"      {row['feature']:20} {row['importance']:.3f} {bar}")

print("\n" + "="*70)
print("       MODEL COMPARISON SUMMARY")
print("="*70)

print("""
+---------------------+----------------------+----------------------+
|                     | ISOLATION FOREST     | RANDOM FOREST        |
+---------------------+----------------------+----------------------+
| Type                | Unsupervised         | Supervised           |
| Labels Required     | No                   | Yes                  |
| Training Speed      | Fast                 | Medium               |
+---------------------+----------------------+----------------------+""")

print(f"| Precision           | {if_results['overall']['precision']:18.1%} | {rf_metrics['accuracy']:18.1%}* |")
print(f"| Recall              | {if_results['overall']['recall']:18.1%} | (see report above)   |")
print(f"| F1-Score            | {if_results['overall']['f1']:18.1%} | (see report above)   |")
print("+---------------------+----------------------+----------------------+")
print("* Random Forest accuracy (different metric)")

print("\n[DONE] Comparison complete!")
print("\nConclusion:")
print("- Isolation Forest: Good for detecting unknown anomalies without labels")
print("- Random Forest: Higher accuracy when you have labeled training data")
print("- Best approach: Use both together for robust detection!")
