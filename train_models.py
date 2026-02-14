import argparse
import sys
from cicids_loader import load_cicids, extract_cicids_features
from model import train_isolation_forest
from model_rf import prepare_supervised_data, train_random_forest, print_rf_report

def main():
    parser = argparse.ArgumentParser(description="Train AnomXShield Models")
    parser.add_argument("--data", type=str, default="data/CICIDS2017_ALL.csv", help="Path to CICIDS2017 CSV file")
    parser.add_argument("--sample", type=float, default=0.1, help="Fraction of data to use for training")
    args = parser.parse_args()

    print("="*60)
    print("       ANOMXSHIELD - MODEL TRAINING")
    print("="*60)

    # 1. Load Data
    print(f"\n[1/4] Loading dataset from {args.data}...")
    try:
        df = load_cicids(args.data)
        if args.sample < 1.0:
            print(f"      Sampling {args.sample:.0%} of data...")
            df = df.sample(frac=args.sample, random_state=42)
        print(f"      Loaded {len(df):,} records")
    except FileNotFoundError:
        print(f"Error: Dataset not found at {args.data}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading data: {e}")
        sys.exit(1)

    # 2. Train Isolation Forest
    print("\n[2/4] Training Isolation Forest (Unsupervised)...")
    try:
        features = extract_cicids_features(df)
        train_isolation_forest(features)
        print("      Isolation Forest trained and saved successfully.")
    except Exception as e:
        print(f"Error training Isolation Forest: {e}")

    # 3. Train Random Forest
    print("\n[3/4] Training Random Forest (Supervised)...")
    try:
        X, y = prepare_supervised_data(df)
        print(f"      Training on {len(X):,} flow-aggregated records...")
        model, metrics, _, _ = train_random_forest(X, y)
        print("      Random Forest trained and saved successfully.")
        
        # 4. Show Results
        print("\n[4/4] Random Forest Performance:")
        print_rf_report(metrics)
        
    except Exception as e:
        print(f"Error training Random Forest: {e}")

    print("\n" + "="*60)
    print("       TRAINING COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
