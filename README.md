# AnomXShield

**AI-Powered Network Intrusion Detection System**

A machine learning-based network intrusion detection system using dual-model approach (Isolation Forest + Random Forest) on the CICIDS2017 dataset, with a modern web dashboard for visualization.

## Features

- **Dual-Model Detection**: Uses both Isolation Forest (unsupervised) and Random Forest (supervised) for comprehensive threat detection
- **10 High-Impact Features**: Expanded from 4 to 10 features including TCP flags, bidirectional traffic, and timing metrics
- **99.7% Accuracy**: Random Forest achieves exceptional accuracy with extended feature set
- **Multi-Attack Detection**: Detects DDoS, PortScan, Brute Force, and other attacks
- **Model Comparison**: Side-by-side comparison of both ML models with detailed metrics
- **Modern Web Dashboard**: Dark-themed UI with real-time charts and live simulation
- **Comprehensive Metrics**: Precision, Recall, F1-Score, Accuracy, and confusion matrices

## Quick Start

### 1. Install Dependencies
```bash
pip install flask pandas scikit-learn
```

### 2. Run the Dashboard
```bash
python app.py
```

### 3. Open in Browser
Navigate to: **http://localhost:5000**

## Project Structure

```
AnomXShield/
├── app.py              # Flask web server with dual-model support
├── main_cicids.py      # Command-line analysis script (both models)
├── compare_models.py   # Standalone model comparison script
├── model.py            # Isolation Forest ML model (unsupervised)
├── model_rf.py         # Random Forest ML model (supervised)
├── rules.py            # Rule-based attack detection
├── detector.py         # Final decision logic for both models
├── evaluation.py       # Metrics calculation
├── cicids_loader.py    # Dataset loading/preprocessing
├── templates/
│   └── index.html      # Dashboard template
├── static/
│   ├── style.css       # Dark theme styling
│   └── app.js          # Frontend logic
├── tests/
│   └── test_core.py    # Unit tests
└── data/
    └── CICIDS2017_ALL.csv  # Dataset
```

## Usage

### Web Dashboard
The dashboard provides:
- **Stats Cards**: Total ports, threats detected, precision, recall
- **Charts**: Attack distribution pie chart, detection rate bar chart
- **Anomalies Table**: Top threats sorted by anomaly score
- **Live Mode**: Simulated real-time detection feed
- **Confusion Matrix**: Model performance visualization
- **Model Comparison**: Compare Isolation Forest vs Random Forest metrics

### Command Line
Run dual-model analysis:
```bash
python main_cicids.py
```

Compare models only:
```bash
python compare_models.py
```

### Run Tests
```bash
python -m pytest tests/ -v
```

## Dataset

Uses the **CICIDS2017** dataset - a benchmark dataset for network intrusion detection containing:
- Benign traffic
- DDoS attacks
- Port scanning
- Brute force attempts
- Web attacks
- And more...

## How It Works

1. **Load Data**: Reads network flow data from CSV
2. **Feature Extraction**: Aggregates 10 per-port features (packets, bytes, TCP flags, timing, etc.)
3. **Dual-Model Training**: 
   - **Isolation Forest**: Unsupervised anomaly detection (no labels needed)
   - **Random Forest**: Supervised classification with 99.7% accuracy (uses attack labels)
4. **Rule-Based Check**: Applies threshold rules for known attack patterns
5. **Final Decision**: Combines ML predictions and rules for classification
6. **Model Comparison**: Displays side-by-side metrics and performance
7. **Visualization**: Shows results in web dashboard with both models

## Credits

Built for educational/learning purposes. Uses scikit-learn for ML and Flask for web framework.
