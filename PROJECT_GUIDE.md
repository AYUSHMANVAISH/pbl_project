# AnomXShield — Complete Project Guide

> A comprehensive reference explaining every feature, algorithm, metric, and technical term used in this AI-Powered Network Intrusion Detection System.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Dataset — CICIDS2017](#2-dataset--cicids2017)
3. [Network Features (10-Feature Set)](#3-network-features-10-feature-set)
4. [Machine Learning Models](#4-machine-learning-models)
5. [Detection Modes](#5-detection-modes)
6. [Rule-Based Detection Engine](#6-rule-based-detection-engine)
7. [Hybrid Decision Engine](#7-hybrid-decision-engine)
8. [Evaluation Metrics](#8-evaluation-metrics)
9. [Attack Types in CICIDS2017](#9-attack-types-in-cicids2017)
10. [Dashboard & API](#10-dashboard--api)
11. [Architecture Overview](#11-architecture-overview)
12. [File Reference](#12-file-reference)

---

## 1. Project Overview

**AnomXShield** is an AI-powered Network Intrusion Detection System (NIDS) that uses machine learning to detect cyber attacks in network traffic. It combines:

- **Unsupervised learning** (Isolation Forest) — detects anomalies without labeled data
- **Supervised learning** (Random Forest) — classifies traffic using labeled attack data
- **Rule-based detection** — domain-specific heuristics for known attack patterns
- **Hybrid decision engine** — combines all three for maximum accuracy

The system analyzes the CICIDS2017 benchmark dataset and provides a real-time web dashboard for visualizing threats.

---

## 2. Dataset — CICIDS2017

### What is it?
The **Canadian Institute for Cybersecurity Intrusion Detection System 2017** dataset. It contains realistic network traffic captured over 5 days, with both normal (benign) and attack traffic labeled.

### Why is it used?
- Industry-standard benchmark for evaluating intrusion detection systems
- Contains **2.8 million+ network flows** with ground truth labels
- Covers **14 different attack types** across multiple categories
- Realistic traffic patterns captured from a real network environment

### How is it used?
- Loaded from `data/CICIDS2017_ALL.csv` via `cicids_loader.py`
- Each row represents one **network flow** (a sequence of packets between two endpoints)
- The `Label` column contains the ground truth: `BENIGN` or the specific attack name
- A configurable sample fraction (default 10%) is used for faster analysis

### Key Terms

| Term | Meaning |
|------|---------|
| **Network Flow** | A sequence of packets between a source and destination IP/port pair, defined by a 5-tuple (src IP, dst IP, src port, dst port, protocol) |
| **Benign Traffic** | Normal, non-malicious network activity |
| **Ground Truth** | The actual correct label — what the traffic really is (attack or benign) |
| **Sampling** | Taking a random subset of the data (e.g., 5-10%) to speed up training and analysis |

---

## 3. Network Features (10-Feature Set)

AnomXShield extracts **10 high-impact features** from each network flow. These features capture different aspects of network behavior that help distinguish attacks from normal traffic.

### Feature Table

| # | Feature | Raw Column | What It Measures | Why It Matters |
|---|---------|-----------|------------------|----------------|
| 1 | **`port`** | `Destination Port` | The destination port number (e.g., 80=HTTP, 443=HTTPS, 22=SSH) | Different attacks target different services; port is the primary grouping key |
| 2 | **`packets_per_sec`** | `Flow Packets/s` | Number of packets sent per second in the flow | High packet rates indicate flooding attacks (DDoS, DoS) |
| 3 | **`total_fwd_packets`** | `Total Fwd Packets` | Total packets sent from source → destination | Unusually high counts suggest automated tools or attacks |
| 4 | **`duration`** | `Flow Duration` | How long the flow lasted (microseconds) | Short bursts suggest scans/brute force; long flows suggest infiltration |
| 5 | **`total_bwd_packets`** | `Total Backward Packets` | Total packets sent from destination → source (response) | Asymmetric ratios (many fwd, few bwd) indicate one-way attacks |
| 6 | **`bytes_per_sec`** | `Flow Bytes/s` | Data volume transferred per second | High bandwidth flows indicate data exfiltration or volumetric DDoS |
| 7 | **`syn_count`** | `SYN Flag Count` | Number of TCP SYN flags in the flow | SYN floods are a classic DDoS technique; high SYN with no ACK = attack |
| 8 | **`ack_count`** | `ACK Flag Count` | Number of TCP ACK flags in the flow | ACK combined with SYN indicates established connections vs. half-open attacks |
| 9 | **`iat_mean`** | `Flow IAT Mean` | Mean Inter-Arrival Time between packets | Regular, machine-like timing suggests automated attacks; irregular = human |
| 10 | **`avg_pkt_size`** | `Average Packet Size` | Mean size of packets in bytes | Small packets = control traffic/scans; large packets = data transfer/exfiltration |

### Key Terms

| Term | Meaning |
|------|---------|
| **Forward Packets** | Packets traveling from the connection initiator (client) to the responder (server) |
| **Backward Packets** | Packets traveling from the responder back to the initiator (responses) |
| **SYN Flag** | TCP flag used to initiate a connection (part of the 3-way handshake: SYN → SYN-ACK → ACK) |
| **ACK Flag** | TCP flag used to acknowledge received data |
| **IAT (Inter-Arrival Time)** | Time gap between consecutive packets — reveals timing patterns |
| **Feature Aggregation** | In port-level mode, per-flow features are aggregated (mean/sum) per destination port |

---

## 4. Machine Learning Models

### 4.1 Isolation Forest (Unsupervised)

**File:** `model.py`

#### What is it?
An **unsupervised anomaly detection** algorithm. It does NOT need labeled training data — it learns what "normal" looks like and flags anything different as anomalous.

#### Why is it used?
- Works without labels — useful when you don't know what attacks look like
- Excellent at finding **unknown/zero-day attacks** that haven't been seen before
- Fast training and prediction
- Acts as a "first line of defense" catching unusual traffic patterns

#### How does it work?
1. Builds an ensemble of **100 random decision trees** (isolation trees)
2. Each tree randomly selects a feature and a split point to partition the data
3. **Anomalies are isolated quickly** (in fewer splits) because they are rare and different
4. Normal points take many splits to isolate because they cluster together
5. The **anomaly score** = average path length across all trees (shorter path = more anomalous)

#### Key Parameters

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `n_estimators` | 100 | Number of isolation trees in the ensemble |
| `contamination` | 0.1 | Expected proportion of anomalies (10%) — tells the model how aggressively to flag |
| `random_state` | 42 | Seed for reproducibility — ensures same results every run |

#### Output
- **Prediction**: `1` = normal, `-1` = anomaly (sklearn convention)
- **Anomaly Score**: Higher = more anomalous (inverted from sklearn's `decision_function`)

---

### 4.2 Random Forest (Supervised)

**File:** `model_rf.py`

#### What is it?
A **supervised classification** algorithm. It uses labeled training data (flows marked as "BENIGN" or "ATTACK") to learn patterns and classify new traffic.

#### Why is it used?
- **High accuracy** (99.6% on this dataset) because it learns from labeled examples
- Can distinguish between different attack types
- Provides **probability scores** (confidence in predictions)
- Robust against overfitting due to ensemble averaging
- Serves as the primary detector in **flow-level mode**

#### How does it work?
1. Converts labels to binary: `BENIGN=0`, any attack=`1`
2. Splits data into **80% training / 20% testing** (stratified to maintain class balance)
3. Builds **100 decision trees**, each trained on a random subset of the data
4. Each tree votes on whether a flow is attack or benign
5. Final prediction = **majority vote** across all trees
6. Also outputs a **probability** (% of trees that voted "attack")

#### Key Parameters

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `n_estimators` | 100 | Number of decision trees in the forest |
| `max_depth` | 20 | Maximum depth of each tree (prevents overfitting) |
| `min_samples_split` | 5 | Minimum samples needed to split a node |
| `n_jobs` | -1 | Use all CPU cores for parallel training |
| `test_size` | 0.2 | Reserve 20% of data for evaluation |
| `stratify` | y | Ensure train/test splits have same attack/benign ratio |

#### Key Terms

| Term | Meaning |
|------|---------|
| **Supervised Learning** | Model learns from labeled training data (knows the correct answer during training) |
| **Unsupervised Learning** | Model learns patterns without labels (discovers structure on its own) |
| **Ensemble Method** | Combining multiple weak models (trees) to create a stronger one |
| **Stratified Split** | Maintaining the same class distribution (attack %) in both train and test sets |
| **Probability Score** | Confidence level (0.0–1.0) that a flow is an attack, based on tree voting |
| **Feature Importance** | How much each feature contributes to predictions — higher importance = more useful for detection |

---

## 5. Detection Modes

### 5.1 Port-Level Aggregation (Original)

**How it works:**
1. All flows are grouped by **destination port**
2. Features are **aggregated** (averaged/summed) per port
3. Each port gets a single prediction: attack or normal
4. Good for broad overview but loses per-flow detail

**Limitations:**
- A port with 99% benign traffic and 1% attack traffic gets averaged, potentially hiding the attack
- Lower recall because individual attack flows are diluted

### 5.2 Flow-Level Detection (Default)

**File:** `flow_detection.py`

**How it works:**
1. Each individual flow is classified by the Random Forest
2. Predictions are then **aggregated back to ports** using a threshold
3. A port is marked **malicious** if ≥30% of its flows are attacks

**Why is it better?**
- **Every single flow** gets its own prediction — no information loss
- Catches attacks even on ports with mostly benign traffic
- Results in **99%+ precision and recall** vs much lower in port mode
- More granular threat levels (Critical, High, Medium)

#### Aggregation & Threat Levels

| Attack Ratio | Threat Level | Meaning |
|-------------|-------------|---------|
| ≥ 80% | **Critical Threat** | Nearly all flows on this port are attacks |
| ≥ 50% | **High Threat** | Majority of flows are attacks |
| ≥ 30% | **Medium Threat** | Significant minority of flows are attacks |
| < 30% | **Normal Traffic** | Below threshold — considered safe |

#### Key Terms

| Term | Meaning |
|------|---------|
| **Aggregation Threshold** | The minimum percentage (default 30%) of attack flows needed to mark a port as malicious |
| **Attack Ratio** | Proportion of flows on a port that are predicted as attacks |
| **Flow-Level Prediction** | Classifying each individual network flow independently |
| **Port-Level Aggregation** | Combining flow predictions into a single per-port decision |

---

## 6. Rule-Based Detection Engine

**File:** `rules.py`

### What is it?
A set of **hardcoded heuristic rules** based on domain knowledge of network security. These rules detect known attack patterns using threshold values.

### Why is it used?
- **Explainable** — you can clearly state why something was flagged ("packet rate > 500/s")
- **Fast** — simple threshold comparisons, no model needed
- **Complementary** — catches patterns that ML models might miss
- Acts as a "sanity check" layer on top of ML predictions

### Detection Rules

| Rule | Condition | Attack Type |
|------|-----------|-------------|
| **DDoS Detection** | `request_rate > 500` OR `request_count > 2500` | DDoS Attack |
| **Port Scan Detection** | `request_rate > 300` AND `request_count < 2500` | PortScan Attack |
| **Brute Force Detection** | `request_count > 50` AND `avg_duration < 100` | Brute Force Attack |
| **High Volume Detection** | `request_count > 1000` | High Volume Traffic |

### Key Terms

| Term | Meaning |
|------|---------|
| **Heuristic** | A practical rule-of-thumb based on domain expertise, not learned from data |
| **Threshold** | A boundary value — traffic above the threshold is flagged as suspicious |
| **Rule-Based Detection** | Using predefined conditions (if-then rules) to identify attacks |

---

## 7. Hybrid Decision Engine

**File:** `detector.py`

### What is it?
The final decision-maker that **combines rule-based detection with ML predictions** to produce the ultimate threat classification.

### Why is it used?
- Rules catch known patterns with certainty
- ML catches unknown patterns probabilistically
- Combining both gives the **best of both worlds**

### Decision Flow

```
Input Flow → Rule Engine → Match? → YES → Return specific attack type
                              ↓
                              NO
                              ↓
                     ML Prediction → Attack?
                              ↓           ↓
                             YES          NO
                              ↓           ↓
                     Check Probability   Check Probability
                              ↓           ↓
                     > 0.8 → "High Confidence Attack"
                     > 0.5 → "Medium Confidence Attack"
                     > 0.3 → "Low Confidence Attack"
                     ≤ 0.3 → "Suspected Anomalous Traffic"
                                        > 0.3 → "Suspected Anomalous Traffic"
                                        ≤ 0.3 → "Normal Traffic"
```

### Confidence Tiers

| Probability | Classification | Meaning |
|------------|---------------|---------|
| Rule match | Specific attack type (e.g., "DDoS Attack") | Rule engine confirmed a known pattern |
| > 80% | High Confidence Attack | ML is very sure this is an attack |
| > 50% | Medium Confidence Attack | ML leans toward attack but not certain |
| > 30% | Low Confidence Attack | ML slightly suspects an attack |
| > 30% (benign pred) | Suspected Anomalous Traffic | ML predicted benign but with notable attack probability |
| ≤ 30% | Normal Traffic | Confidently benign |

---

## 8. Evaluation Metrics

**File:** `evaluation.py`

### 8.1 Confusion Matrix

A 2×2 table showing how predictions compare to reality:

|  | **Predicted: Attack** | **Predicted: Normal** |
|---|---|---|
| **Actual: Attack** | ✅ True Positive (TP) | ❌ False Negative (FN) |
| **Actual: Normal** | ❌ False Positive (FP) | ✅ True Negative (TN) |

- **TP (True Positive):** Correctly detected an attack → Good!
- **TN (True Negative):** Correctly identified normal traffic → Good!
- **FP (False Positive):** Normal traffic flagged as attack → "False alarm"
- **FN (False Negative):** Attack missed, classified as normal → Dangerous!

### 8.2 Precision

```
Precision = TP / (TP + FP)
```

**What it means:** Of everything we flagged as an attack, what percentage actually was an attack?

**Why it matters:** High precision = few false alarms. Important so security teams don't waste time investigating benign traffic.

**Our result:** **99.2%** — almost every alert is a real threat.

### 8.3 Recall (Sensitivity)

```
Recall = TP / (TP + FN)
```

**What it means:** Of all actual attacks, what percentage did we detect?

**Why it matters:** High recall = few missed attacks. Critical for security — a missed attack could mean a breach.

**Our result:** **98.8%** — we catch nearly every attack.

### 8.4 F1 Score

```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

**What it means:** The harmonic mean of precision and recall. A single number that balances both.

**Why it matters:** Useful when you want one metric to summarize detection quality. F1 = 1.0 is perfect.

**Our result:** **99.0%** — excellent balance of precision and recall.

### 8.5 Accuracy

```
Accuracy = (TP + TN) / (TP + TN + FP + FN)
```

**What it means:** What percentage of all predictions (attack and normal) were correct?

**Our result:** **99.6%**

### 8.6 Detection Rate (Per Attack Type)

```
Detection Rate = Detected Attacks / Total Attacks × 100%
```

**What it means:** For a specific attack type (e.g., DDoS), what percentage of those attacks did we catch?

**Why it matters:** Reveals which attack types the model is good/bad at detecting.

---

## 9. Attack Types in CICIDS2017

| Attack Type | Category | Description | Detection Rate |
|------------|----------|-------------|---------------|
| **DDoS** | Volumetric | Distributed Denial of Service — overwhelming a server with traffic from multiple sources | 99.8% |
| **DoS Hulk** | Volumetric | DoS attack using the Hulk tool — generates high volume of unique HTTP requests | 99.6% |
| **DoS GoldenEye** | Volumetric | DoS attack using GoldenEye tool — HTTP flood targeting web servers | 97.5% |
| **DoS Slowhttptest** | Slow-Rate | Keeps HTTP connections open with slow, incomplete headers — stalls the server | 100% |
| **DoS slowloris** | Slow-Rate | Similar to Slowhttptest — holds connections open by sending partial HTTP headers | 99.7% |
| **PortScan** | Reconnaissance | Probing multiple ports on a target to find open services — precursor to attacks | 100% |
| **FTP-Patator** | Brute Force | Automated brute-force password guessing on FTP (File Transfer Protocol) services | 100% |
| **SSH-Patator** | Brute Force | Automated brute-force password guessing on SSH (Secure Shell) services | 99.3% |
| **Bot** | Malware | Infected machines (bots) communicating with command-and-control servers | 56.7% |
| **Heartbleed** | Exploit | Exploiting the OpenSSL heartbeat vulnerability to leak server memory | 0% (only 2 samples) |
| **Web Attack – Brute Force** | Web | Brute-force login attempts on web applications | 23.4% |
| **Web Attack – XSS** | Web | Cross-Site Scripting injection attacks on web forms | 3.2% |

> **Note:** Low detection rates for Bot, Heartbleed, and Web Attacks are expected — these attacks have very few samples in the dataset and produce subtle traffic patterns that closely resemble normal activity.

---

## 10. Dashboard & API

### Web Dashboard

**Files:** `templates/index.html`, `static/style.css`, `static/app.js`

The dashboard provides real-time visualization of detection results:

| Component | What It Shows |
|-----------|--------------|
| **Status Bar** | Current system state (Initializing / Analysis Complete / LIVE) |
| **Total Ports Analyzed** | Number of unique destination ports in the dataset |
| **Threats Detected** | Number of ports classified as malicious |
| **Precision** | RF model precision (% of alerts that are real threats) |
| **Recall** | RF model recall (% of real attacks that were detected) |
| **Attack Distribution** | Pie/doughnut chart showing threat level breakdown |
| **Detection by Attack Type** | Horizontal bar chart with per-attack detection rates |
| **Top Anomalies** | Table of highest-risk ports with threat scores |
| **Live Detection Feed** | Real-time flow-by-flow scanning simulation |
| **Confusion Matrix** | TP / FP / TN / FN counts |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML page |
| `/api/status` | GET | Check if analysis is loaded |
| `/api/analyze` | POST | Run ML analysis (accepts `sample_frac`, `mode`, `aggregation_threshold`) |
| `/api/stats` | GET | Get statistics, metrics, per-attack detection rates |
| `/api/anomalies` | GET | Get top anomalous ports ranked by threat score |
| `/api/live` | GET | Get a random flow with its ML prediction (for live scanning) |
| `/api/scores` | GET | Get anomaly score distribution |
| `/api/model/rf` | GET | Get Random Forest metrics and feature importance |
| `/api/model/compare` | GET | Compare Isolation Forest vs Random Forest |

### Live Mode

**How it works:**
1. The JavaScript frontend polls `/api/live` every 1.2 seconds
2. The backend picks a **random flow** from the analyzed dataset
3. Returns the flow's port, ML prediction, confidence score, and ground truth label
4. The feed displays results color-coded: 🚨 red for attacks, ⚠️ yellow for suspected, ✅ green for normal

---

## 11. Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                  CICIDS2017 CSV                  │
│              (2.8M+ network flows)               │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│            Data Loading & Preprocessing          │
│  cicids_loader.py: load_cicids(), extract_features│
│  • Column mapping, NaN/Inf handling              │
│  • 10-feature extraction, port aggregation       │
└────────────────────┬────────────────────────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Isolation │ │  Random  │ │  Rule    │
  │  Forest   │ │  Forest  │ │  Engine  │
  │(Unsup.)   │ │ (Sup.)   │ │(Heurist.)│
  │ model.py  │ │model_rf.py│ │ rules.py │
  └─────┬─────┘ └─────┬────┘ └─────┬────┘
        │              │            │
        └──────────────┼────────────┘
                       ▼
        ┌──────────────────────────┐
        │   Hybrid Decision Engine  │
        │       detector.py         │
        │ Combines all three for    │
        │ final threat classification│
        └──────────────┬───────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Per-Port │ │ Per-Flow │ │Evaluation│
  │ Results  │ │ Results  │ │ Metrics  │
  │          │ │flow_det. │ │eval.py   │
  └──────────┘ └──────────┘ └──────────┘
                       │
                       ▼
        ┌──────────────────────────┐
        │     Flask Web Server      │
        │        app.py             │
        │   REST API + Dashboard    │
        └──────────────────────────┘
```

---

## 12. File Reference

| File | Purpose |
|------|---------|
| `app.py` | Flask web server, API endpoints, analysis orchestration |
| `cicids_loader.py` | Load and preprocess CICIDS2017 CSV, extract 10 features |
| `model.py` | Train Isolation Forest, compute anomaly scores |
| `model_rf.py` | Train Random Forest, predict with probabilities, feature importance |
| `detector.py` | Hybrid decision engine combining rules + ML |
| `rules.py` | Rule-based detection with configurable thresholds |
| `flow_detection.py` | Flow-level detection and port aggregation |
| `evaluation.py` | Precision, recall, F1, confusion matrix, per-attack evaluation |
| `templates/index.html` | Dashboard HTML layout |
| `static/app.js` | Dashboard JavaScript — chart rendering, live mode, API calls |
| `static/style.css` | Dashboard CSS — dark theme styling |
| `tests/test_core.py` | Unit tests for rules, models, evaluation, detector |

---

## Glossary

| Term | Definition |
|------|-----------|
| **NIDS** | Network Intrusion Detection System — monitors network traffic for suspicious activity |
| **IDS** | Intrusion Detection System — broader category including host-based and network-based |
| **Flow** | A bidirectional sequence of packets between two endpoints (defined by 5-tuple) |
| **5-Tuple** | Source IP, Destination IP, Source Port, Destination Port, Protocol — uniquely identifies a flow |
| **Anomaly Detection** | Finding data points that deviate significantly from the norm |
| **Classification** | Categorizing data points into predefined classes (attack vs. benign) |
| **Contamination** | Expected proportion of anomalies in the dataset (Isolation Forest parameter) |
| **Ensemble** | Combining multiple models to produce better predictions than any single model |
| **Decision Tree** | A flowchart-like model that makes decisions by splitting on feature values |
| **Overfitting** | When a model memorizes training data instead of learning general patterns |
| **Stratification** | Ensuring class proportions are maintained when splitting data |
| **TCP** | Transmission Control Protocol — reliable, connection-oriented protocol (uses SYN/ACK handshake) |
| **DDoS** | Distributed Denial of Service — flooding a target from multiple sources |
| **DoS** | Denial of Service — overwhelming a target to make it unavailable |
| **Brute Force** | Systematically trying all possible passwords/keys until the correct one is found |
| **Port Scan** | Sending packets to a range of ports to discover which services are running |
| **XSS** | Cross-Site Scripting — injecting malicious scripts into web pages |
| **Bot/Botnet** | Network of infected computers controlled remotely by an attacker |
| **Heartbleed** | OpenSSL vulnerability (CVE-2014-0160) allowing memory leakage from servers |
| **Zero-Day** | An attack exploiting a previously unknown vulnerability |
