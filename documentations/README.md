# Port Scanning Attack Detection with AI

## Project Overview
This project implements an automated port scanning attack scenario using Mininet and detects the attack using AI/ML techniques (Random Forest Classifier and Isolation Forest).

**Course:** AI in sisteme de securitate informatica
**Attack Type:** TCP SYN Port Scanning  
**Detection Method:** Machine Learning (Random Forest) + Unsupervised Anomaly Detection

---

## Project Structure

```
Proiect1/
├── port_scan_attack.py       # Main attack simulation (Mininet)
├── feature_extraction.py      # Extract features from traffic
├── traffic_detector.py        # AI-based attack detection
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── rstattack.py              # Reference example (RST attack)
```

---

## Attack Scenario

### Network Topology
```
h1 (Victim Server) --- s1 (Switch) --- h2 (Legitimate Client)
                        |
                       h3 (Attacker)
```

### Attack Description
- **Type:** TCP SYN Port Scanning
- **Attacker:** h3 scans ports 1-1000 on victim h1
- **Legitimate Traffic:** h2 performs normal HTTP and iperf traffic to h1
- **Timeline:**
  - 0-10s: Normal traffic only
  - 10-30s: Attack + Normal traffic
  - 30-50s: Normal traffic only

---

## Installation

### System Requirements
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y mininet tcpdump tshark iperf tcpreplay python3-pip

# Install Python packages
pip3 install -r requirements.txt
```
## Usage

### Step 1: Run Attack Simulation
```bash
sudo python3 port_scan_attack.py
```

**What it does:**
- Creates Mininet network topology
- Starts victim services (HTTP server, iperf)
- Captures traffic on all hosts (tcpdump)
- Generates legitimate traffic (h2 → h1)
- Executes port scan attack (h3 → h1)
- Exports traffic to CSV files

**Output files:**
- `/tmp/h1.pcap`, `/tmp/h1.csv` (Victim)
- `/tmp/h2.pcap`, `/tmp/h2.csv` (Legitimate client)
- `/tmp/h3.pcap`, `/tmp/h3.csv` (Attacker)

### Step 2: Extract Features
```bash
python3 feature_extraction.py /tmp/h1.csv /tmp/h1_features.csv 1.0
```

**Parameters:**
- Input CSV file
- Output features file
- Time window size (seconds)

**Extracted Features:**
- Packets per second
- Bytes per second
- Unique destination ports (KEY for port scan detection!)
- Port diversity ratio
- SYN/ACK ratio
- TCP flags distribution
- Protocol ratios (TCP/UDP/ICMP)
- Connection patterns

### Step 3: Detect Attack with AI
```bash
python3 traffic_detector.py /tmp/h1_features.csv 10 30
```

**Parameters:**
- Features CSV file
- Attack start time (seconds)
- Attack end time (seconds)

**Detection Methods:**

1. **Supervised Learning (Random Forest)**
   - Trains on labeled data (normal vs attack)
   - 70/30 train-test split
   - Reports accuracy, precision, recall, F1-score
   - Shows feature importance

2. **Unsupervised Learning (Isolation Forest)**
   - Detects anomalies without labels
   - Good for unknown attack patterns
   - Identifies outliers based on feature distribution

**Output files:**
- `feature_importance.csv`: Most important features for detection
- `detection_results.png`: Visualization plots

---

## Key Features for Attack Detection

The AI model identifies port scanning based on these features:

| Feature | Normal Traffic | Port Scan Attack |
|---------|----------------|------------------|
| **unique_dst_ports** | Low (1-5) | **High (100-1000)** ⭐ |
| **port_diversity** | Low (~0.01) | **High (~0.9)** ⭐ |
| **syn_ack_ratio** | ~1.0 | **High (>2)** ⭐ |
| **packets_per_second** | Moderate | Very High |
| **syn_count** | Low | Very High |

⭐ = Most important features

---

## Example Results

### Expected Output
```
MODEL EVALUATION
================================================================
Accuracy: 0.9850 (98.50%)

Classification Report:
              precision    recall  f1-score   support

      Normal       0.99      0.98      0.98        50
      Attack       0.98      0.99      0.99        50

    accuracy                           0.98       100
   macro avg       0.98      0.98      0.98       100
weighted avg       0.98      0.98      0.98       100

Confusion Matrix:
[[49  1]
 [ 1 49]]

True Negatives: 49 | False Positives: 1
False Negatives: 1 | True Positives: 49

FEATURE IMPORTANCE (Top 10)
================================================================
           feature  importance
  unique_dst_ports    0.285432
   port_diversity    0.241287
     syn_ack_ratio    0.156734
         syn_count    0.098123
packets_per_second    0.067891
```

---

## How It Works

### 1. Attack Generation (Scapy)
```python
# Creates SYN packets to ports 1-1000
for port in range(1, 1001):
    pkt = IP(dst=target)/TCP(dport=port, flags='S')
    packets.append(pkt)
```

### 2. Feature Extraction
- Processes traffic in 1-second time windows
- Calculates statistical features per window
- Key insight: Port scans access MANY different ports rapidly

### 3. ML Detection
```python
# Random Forest trained on features
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Detects based on learned patterns
prediction = model.predict(features)
```

---

## AI Techniques Used

### 1. Random Forest Classifier (Supervised)
- **Type:** Ensemble learning method
- **How it works:** Creates multiple decision trees and combines their predictions
- **Advantages:**
  - High accuracy
  - Handles non-linear relationships
  - Provides feature importance
  - Robust to overfitting

### 2. Isolation Forest (Unsupervised)
- **Type:** Anomaly detection algorithm
- **How it works:** Isolates anomalies by randomly partitioning data
- **Advantages:**
  - No labels needed
  - Detects unknown attack patterns
  - Fast and efficient

### 3. Standard Scaling
- Normalizes features to same scale
- Improves ML model performance

---

## Troubleshooting

### WSL2 kernel incopatibility
- USING WSL2 failed for this project since i was unable to use the controller for the mininetwork since the kernel was not supporting this, switched to a virtual machine with ubuntu instead

### Mininet Issues
```bash
# Clean up Mininet
sudo mn -c

# Check if Mininet works
sudo mn --test pingall
```

### Permission Issues
```bash
# Run with sudo for network operations
sudo python3 port_scan_attack.py
```

### Missing tshark
```bash
# Install Wireshark/tshark
sudo apt-get install tshark
```

### CSV Empty or Invalid
- Check if pcap files exist in `/tmp/`
- Verify tshark installed correctly
- Check tshark permissions
---

## References

- [Mininet Documentation](http://mininet.org/)
- [Scapy Documentation](https://scapy.net/)
- [Scikit-learn Random Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)

---

## Final Notes

This project demonstrates:
1. **Network simulation** using Mininet
2. **Attack generation** using Scapy
3. **Feature engineering** from network traffic
4. **Machine Learning** for intrusion detection
5. **Both supervised and unsupervised** learning approaches

The port scanning attack is particularly good for ML because:
- Clear distinguishing features (unique ports, port diversity)
- High detection accuracy achievable
- Real-world relevance (port scans are reconnaissance for attacks)
- Multiple detection approaches possible