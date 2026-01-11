#!/bin/bash
# Quick Start Script for Port Scan Attack Detection Project
# Run this script to execute the complete experiment

echo "=========================================="
echo "Port Scan Attack Detection - Quick Start"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (use sudo)"
    echo "Usage: sudo ./run_experiment.sh"
    exit 1
fi

# Step 1: Run attack simulation
echo ""
echo "Step 1: Running attack simulation..."
echo "--------------------------------------"
python3 port_scan_attack.py
if [ $? -ne 0 ]; then
    echo "ERROR: Attack simulation failed!"
    exit 1
fi

echo ""
echo "Attack simulation completed!"
echo ""
echo "Press Enter to continue with feature extraction..."
read

# Step 2: Extract features from all hosts
echo ""
echo "Step 2: Extracting features..."
echo "--------------------------------------"

for host in h1 h2 h3; do
    echo "Extracting features from ${host}..."
    python3 feature_extraction.py /tmp/${host}.csv /tmp/${host}_features.csv 1.0
    if [ $? -ne 0 ]; then
        echo "WARNING: Feature extraction failed for ${host}"
    fi
done

echo ""
echo "Feature extraction completed!"
echo ""
echo "Press Enter to continue with AI detection..."
read

# Step 3: Run AI-based detection on victim (h1)
echo ""
echo "Step 3: Running AI-based detection on h1 (victim)..."
echo "--------------------------------------"
python3 traffic_detector.py /tmp/h1_features.csv 10 30
if [ $? -ne 0 ]; then
    echo "ERROR: Detection failed!"
    exit 1
fi

# Summary
echo ""
echo "=========================================="
echo "EXPERIMENT COMPLETED SUCCESSFULLY!"
echo "=========================================="
echo ""
echo "Generated files:"
echo "  Traffic captures:"
echo "    - /tmp/h1.pcap, /tmp/h1.csv (Victim)"
echo "    - /tmp/h2.pcap, /tmp/h2.csv (Legitimate client)"
echo "    - /tmp/h3.pcap, /tmp/h3.csv (Attacker)"
echo ""
echo "  Feature files:"
echo "    - /tmp/h1_features.csv"
echo "    - /tmp/h2_features.csv"
echo "    - /tmp/h3_features.csv"
echo ""
echo "  Analysis results:"
echo "    - feature_importance.csv"
echo "    - detection_results.png"
echo ""
echo "You can now:"
echo "  1. View visualizations: xdg-open detection_results.png"
echo "  2. Analyze features: cat feature_importance.csv"
echo "  3. Inspect traffic: wireshark /tmp/h1.pcap"
echo ""
echo "=========================================="
