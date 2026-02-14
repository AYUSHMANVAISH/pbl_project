from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pandas as pd
import numpy as np
import joblib
import os

MODEL_DIR = 'saved_models'

def save_rf_model(model, metrics, filename='random_forest.pkl'):
    os.makedirs(MODEL_DIR, exist_ok=True)
    path = os.path.join(MODEL_DIR, filename)
    joblib.dump({'model': model, 'metrics': metrics}, path)
    print(f"[+] Random Forest model saved to {path}")

def load_rf_model(filename='random_forest.pkl'):
    path = os.path.join(MODEL_DIR, filename)
    if os.path.exists(path):
        data = joblib.load(path)
        print(f"[+] Random Forest model loaded from {path}")
        return data['model'], data['metrics']
    return None, None

def prepare_supervised_data(df):
    df = df.copy()
    df['is_attack'] = (df['label'].str.upper() != 'BENIGN').astype(int)

    feature_cols = [
        'port',
        'packets_per_sec',
        'total_fwd_packets',
        'duration',
        'total_bwd_packets',
        'bytes_per_sec',
        'syn_count',
        'ack_count',
        'iat_mean',
        'avg_pkt_size'
    ]
    X = df[feature_cols].copy()

    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    y = df['is_attack']

    return X, y

def train_random_forest(X, y, n_estimators=100, random_state=42, test_size=0.2):

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        max_depth=20,
        min_samples_split=5
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'classification_report': classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
    }

    save_rf_model(model, metrics)
    return model, metrics, X_test, y_test

def predict_with_rf(model, X):

    X = X.copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    return predictions, probabilities

def get_feature_importance(model, feature_names):

    importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    return importance

def print_rf_report(metrics):

    print("\n" + "="*60)
    print("      RANDOM FOREST EVALUATION REPORT")
    print("="*60)
    print(f"\nAccuracy: {metrics['accuracy']:.2%}")
    print("\nClassification Report:")
    print(metrics['classification_report'])
    print("\nConfusion Matrix:")
    cm = metrics['confusion_matrix']
    print(f"                  Predicted")
    print(f"                  BENIGN  ATTACK")
    print(f"   Actual BENIGN   {cm[0][0]:6}  {cm[0][1]:6}")
    print(f"   Actual ATTACK   {cm[1][0]:6}  {cm[1][1]:6}")
    print("="*60)

if __name__ == "__main__":
    from cicids_loader import load_cicids
    import argparse

    parser = argparse.ArgumentParser(description="Train Random Forest Model")
    parser.add_argument("--data", type=str, default="data/CICIDS2017_ALL.csv", help="Path to dataset")
    parser.add_argument("--sample", type=float, default=0.1, help="Sampling fraction")
    args = parser.parse_args()

    print(f"Loading data from {args.data}...")
    try:
        df = load_cicids(args.data)
        if args.sample < 1.0:
            df = df.sample(frac=args.sample, random_state=42)
        
        print(f"Preparing data from {len(df)} records...")
        X, y = prepare_supervised_data(df)
        
        print("Training Random Forest...")
        model, metrics, _, _ = train_random_forest(X, y)
        print_rf_report(metrics)
        
    except FileNotFoundError:
        print(f"Error: File {args.data} not found.")
    except Exception as e:
        print(f"Error: {e}")
