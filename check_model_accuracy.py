
import os
import sys
from model_rf import load_rf_model

def check_model():
    print("Checking saved model...")
    model, metrics = load_rf_model()
    if model:
        print(f"Model found.")
        print(f"Accuracy: {metrics.get('accuracy', 'N/A')}")
        if 'classification_report' in metrics:
            print("Classification Report:")
            print(metrics['classification_report'])
    else:
        print("No saved model found.")

def check_datasets():
    print("\nChecking for datasets...")
    data_dir = 'data'
    if os.path.exists(data_dir):
        for root, dirs, files in os.walk(data_dir):
            for file in files:
                if file.endswith(".csv"):
                    print(f"Found dataset: {os.path.join(root, file)}")

if __name__ == "__main__":
    check_model()
    check_datasets()
