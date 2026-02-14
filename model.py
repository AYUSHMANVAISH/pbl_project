from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_DIR = 'saved_models'

def save_model(model, filename='isolation_forest.pkl'):
    os.makedirs(MODEL_DIR, exist_ok=True)
    path = os.path.join(MODEL_DIR, filename)
    joblib.dump(model, path)
    print(f"[+] Isolation Forest model saved to {path}")

def load_model(filename='isolation_forest.pkl'):
    path = os.path.join(MODEL_DIR, filename)
    if os.path.exists(path):
        model = joblib.load(path)
        print(f"[+] Isolation Forest model loaded from {path}")
        return model
    return None

def train_isolation_forest(features, contamination=0.1, random_state=42, n_estimators=100):

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state
    )
    model.fit(features)
    save_model(model)
    return model

def get_anomaly_scores(model, features):

    raw = model.decision_function(features)
    scores = (-raw)
    preds = model.predict(features)

    import pandas as pd
    scores_s = pd.Series(scores, index=features.index, name="anomaly_score")
    preds_s = pd.Series(preds, index=features.index, name="prediction")
    return scores_s, preds_s

if __name__ == "__main__":
    from cicids_loader import load_cicids, extract_cicids_features
    import argparse

    parser = argparse.ArgumentParser(description="Train Isolation Forest Model")
    parser.add_argument("--data", type=str, default="data/CICIDS2017_ALL.csv", help="Path to dataset")
    parser.add_argument("--sample", type=float, default=0.1, help="Sampling fraction")
    args = parser.parse_args()

    print(f"Loading data from {args.data}...")
    try:
        df = load_cicids(args.data)
        if args.sample < 1.0:
            df = df.sample(frac=args.sample, random_state=42)
        
        print(f"Extracting features from {len(df)} records...")
        features = extract_cicids_features(df)
        
        print("Training Isolation Forest...")
        train_isolation_forest(features)
        
    except FileNotFoundError:
        print(f"Error: File {args.data} not found.")
    except Exception as e:
        print(f"Error: {e}")
