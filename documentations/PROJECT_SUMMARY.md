# Project Summary - Port Scan Attack Detection

## Quick Overview

This project implements and detects TCP SYN port scanning attacks using:
- **Mininet** for network simulation
- **Scapy** for packet generation
- **Random Forest** & **Isolation Forest** for AI-based detection

---

## Files Created

| File | Purpose |
|------|---------|
| `port_scan_attack.py` | Main script - creates network, runs attack, captures traffic |
| `feature_extraction.py` | Extracts ML features from traffic CSV |
| `traffic_detector.py` | AI-based detection (Random Forest + Isolation Forest) |
| `test_system.py` | Tests if all dependencies installed |
| `run_experiment.sh` | Automated script to run complete experiment |
| `requirements.txt` | Python dependencies |
| `README.md` | Complete documentation |
| `WINDOWS_SETUP.md` | Windows-specific setup guide |

---

## How to Run

### Complete Automated Run
```bash
# Linux/WSL2 only - runs everything automatically
sudo ./run_experiment.sh
```

### Manual Step-by-Step
```bash
# Step 1: Run attack simulation
sudo python3 port_scan_attack.py

# Step 2: Extract features
python3 feature_extraction.py /tmp/h1.csv /tmp/h1_features.csv 1.0

# Step 3: Detect with AI
python3 traffic_detector.py /tmp/h1_features.csv 10 30
```

---

## Expected Results

```
Accuracy: 95-99%
Precision: 0.95-0.99
Recall: 0.95-0.99

Top Features:
1. unique_dst_ports (28% importance)
2. port_diversity (24% importance)
3. syn_ack_ratio (16% importance)
```

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────┐
│              MININET NETWORK                     │
│  ┌──────┐         ┌──────┐         ┌──────┐      │
│  │  h1  │─────────│  s1  │─────────│  h2  │      │
│  │Victim│         │Switch│         │Client│      │
│  └──────┘         └──────┘         └──────┘      │
│                      │                           │
│                   ┌──────┐                       │
│                   │  h3  │                       │
│                   │Attack│                       │
│                   └──────┘                       │
└──────────────────────────────────────────────────┘
                      │
                      ▼ 
          ┌────────────────────────┐
          │   Traffic Capture      │
          │   (tcpdump → pcap)     │
          └────────────────────────┘
                      │
                      ▼
          ┌────────────────────────┐
          │   Export to CSV        │
          │   (tshark)             │
          └────────────────────────┘
                      │
                      ▼
          ┌────────────────────────┐
          │  Feature Extraction    │
          │  (19 features/window)  │
          └────────────────────────┘
                      │
                      ▼
          ┌────────────────────────┐
          │   ML Detection         │
          │  - Random Forest       │
          │  - Isolation Forest    │
          └────────────────────────┘
                      │
                      ▼
          ┌────────────────────────┐
          │   Results              │
          │  - Accuracy metrics    │
          │  - Visualizations      │
          │  - Feature importance  │
          └────────────────────────┘
```

---

## Timeline of Experiment

```
Time (s)  |  Activity
----------|------------------------------------------
0-2       |  Setup network, start services
2-10      |  Normal traffic only (h2 → h1)
10-30     |  🚨 PORT SCAN ATTACK + normal traffic
30-50     |  Normal traffic resumes
50+       |  Export to CSV, run detection
```

---

## ML Model Details

### Random Forest Classifier
- **Algorithm:** Ensemble of decision trees
- **Parameters:** 100 trees, max depth 10
- **Input:** 19 features per time window
- **Output:** Binary classification (Normal/Attack)

### Isolation Forest
- **Algorithm:** Unsupervised anomaly detection
- **Parameters:** 10% contamination expected
- **Input:** Same 19 features
- **Output:** Anomaly score

### Feature Scaling
- StandardScaler (zero mean, unit variance)
- Prevents feature dominance

---

## Key Features for Detection

| Feature            | Normal | Attack   | Ratio    |
|--------------------|--------|----------|----------|
| unique_dst_ports   | 1-5    | 100-1000 | **200x** |
| port_diversity     | 0.01   | 0.9      | **90x**  |
| syn_ack_ratio      | ~1.0   | >5       | **5x**   |
| packets_per_second | 10-50  | 500+     | **10x+** |

The huge difference makes ML detection very accurate!

---

## Credits & References

- **Mininet:** Network emulation
- **Scapy:** Packet manipulation
- **Scikit-learn:** Machine learning
- **Wireshark/tshark:** Packet analysis
