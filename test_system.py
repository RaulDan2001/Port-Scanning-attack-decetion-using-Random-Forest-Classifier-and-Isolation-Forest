#!/usr/bin/env python3
"""
Test script to verify all components work correctly
Run this to check dependencies before running the full experiment
"""

import sys

def test_imports():
    """Test if all required Python packages are installed"""
    print("="*60)
    print("Testing Python Package Imports")
    print("="*60)
    
    packages = [
        ('scapy', 'scapy.all'),
        ('pandas', 'pandas'),
        ('numpy', 'numpy'),
        ('sklearn', 'sklearn'),
        ('matplotlib', 'matplotlib'),
        ('seaborn', 'seaborn'),
    ]
    
    all_ok = True
    for name, import_name in packages:
        try:
            __import__(import_name)
            print(f" {name:20s} OK")
        except ImportError as e:
            print(f" {name:20s} MISSING - {e}")
            all_ok = False
    
    return all_ok


def test_system_tools():
    """Test if system tools are available"""
    print("\n" + "="*60)
    print("Testing System Tools")
    print("="*60)
    
    import subprocess
    
    tools = [
        'tcpdump',
        'tshark',
        'iperf',
        'tcpreplay'
    ]
    
    all_ok = True
    for tool in tools:
        try:
            result = subprocess.run(
                ['which', tool] if sys.platform != 'win32' else ['where', tool],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                print(f" {tool:20s} OK - {path}")
            else:
                print(f" {tool:20s} NOT FOUND")
                all_ok = False
        except Exception as e:
            print(f" {tool:20s} ERROR - {e}")
            all_ok = False
    
    return all_ok


def test_mininet():
    """Test if Mininet is available"""
    print("\n" + "="*60)
    print("Testing Mininet")
    print("="*60)
    
    try:
        from mininet.net import Mininet
        from mininet.topo import Topo
        print(" Mininet imports OK")
        
        # Try to check if running as root
        import os
        if os.geteuid() == 0:
            print(" Running as root (required for Mininet)")
        else:
            print("Not running as root - Mininet requires sudo!")
            return False
        
        return True
    except ImportError as e:
        print(f" Mininet NOT INSTALLED - {e}")
        return False
    except AttributeError:
        # os.geteuid() not available on Windows
        print("⚠ Cannot check root status (Windows?)")
        print("  Note: Mininet requires Linux or WSL2")
        return False


def test_feature_extraction():
    """Test feature extraction on sample data"""
    print("\n" + "="*60)
    print("Testing Feature Extraction (Sample Data)")
    print("="*60)
    
    try:
        import pandas as pd
        import numpy as np
        
        # Create sample CSV data
        sample_data = pd.DataFrame({
            'frame.time_relative': np.arange(0, 10, 0.1),
            'frame.len': np.random.randint(40, 1500, 100),
            'ip.src': ['10.0.0.1'] * 50 + ['10.0.0.2'] * 50,
            'ip.dst': ['10.0.0.3'] * 100,
            'ip.proto': ['6'] * 80 + ['17'] * 20,
            'tcp.srcport': np.random.randint(1024, 65535, 100),
            'tcp.dstport': np.random.randint(1, 1001, 100),
            'tcp.flags.syn': [1] * 40 + [0] * 60,
            'tcp.flags.ack': [0] * 40 + [1] * 60,
            'tcp.flags.fin': [0] * 100,
            'tcp.flags.reset': [0] * 100,
        })
        
        # Save to temp file
        sample_data.to_csv('/tmp/test_sample.csv', index=False)
        
        # Try to import feature extractor
        from feature_extraction import TrafficFeatureExtractor
        
        extractor = TrafficFeatureExtractor('/tmp/test_sample.csv', window_size=1.0)
        if extractor.load_data():
            features = extractor.extract_features()
            if features is not None and len(features) > 0:
                print(f" Feature extraction OK - {len(features)} windows extracted")
                return True
            else:
                print(" Feature extraction returned no data")
                return False
        else:
            print(" Failed to load sample data")
            return False
            
    except Exception as e:
        print(f" Feature extraction test failed - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ml_models():
    """Test ML models on sample data"""
    print("\n" + "="*60)
    print("Testing ML Models (Sample Data)")
    print("="*60)
    
    try:
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.model_selection import train_test_split
        import numpy as np
        
        # Create sample features
        np.random.seed(42)
        X_normal = np.random.randn(50, 5)
        X_attack = np.random.randn(50, 5) + 3  # Shifted distribution
        
        X = np.vstack([X_normal, X_attack])
        y = np.array([0] * 50 + [1] * 50)
        
        # Train Random Forest
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        rf.fit(X_train, y_train)
        accuracy = rf.score(X_test, y_test)
        
        print(f" Random Forest OK - Test accuracy: {accuracy:.2%}")
        
        # Test Isolation Forest
        iso = IsolationForest(contamination=0.1, random_state=42)
        iso.fit(X)
        predictions = iso.predict(X)
        
        print(f" Isolation Forest OK - Detected {sum(predictions == -1)} anomalies")
        
        return True
        
    except Exception as e:
        print(f" ML models test failed - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print(" PORT SCAN ATTACK DETECTION - SYSTEM TEST")
    print("="*70)
    
    results = {}
    
    # Run tests
    results['Python Packages'] = test_imports()
    results['System Tools'] = test_system_tools()
    results['Mininet'] = test_mininet()
    results['Feature Extraction'] = test_feature_extraction()
    results['ML Models'] = test_ml_models()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    all_passed = True
    for test_name, passed in results.items():
        status = " PASS" if passed else " FAIL"
        print(f"{test_name:25s} {status}")
        if not passed:
            all_passed = False
    
    print("="*70)
    
    if all_passed:
        print("\n All tests passed! System is ready.")
        print("\nNext steps:")
        print("  1. Run: sudo python3 port_scan_attack.py")
        print("  2. Then: python3 feature_extraction.py /tmp/h1.csv")
        print("  3. Then: python3 traffic_detector.py /tmp/h1_features.csv 10 30")
        return 0
    else:
        print("\n Some tests failed. Please fix issues before running the experiment.")
        print("\nInstallation help:")
        print("  Python packages: pip3 install -r requirements.txt")
        print("  System tools: sudo apt-get install tcpdump tshark iperf tcpreplay")
        print("  Mininet: sudo apt-get install mininet")
        return 1


if __name__ == '__main__':
    sys.exit(main())
