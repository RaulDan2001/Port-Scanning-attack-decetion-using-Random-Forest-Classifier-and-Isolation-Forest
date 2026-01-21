#!/usr/bin/env python3
"""
AI-Based Port Scan Attack Detector
Uses Random Forest Classifier for network intrusion detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os


class PortScanDetector:
    """AI-based port scan attack detector"""
    
    def __init__(self, features_file):
        """Initialize detector with features file"""
        self.features_file = features_file
        self.df = None
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def load_features(self):
        """Load extracted features"""
        print(f"Loading features from {self.features_file}...")
        try:
            self.df = pd.read_csv(self.features_file)
            print(f"Loaded {len(self.df)} feature windows")
            print(f"Columns: {list(self.df.columns)}")
            return True
        except Exception as e:
            print(f"Error loading features: {e}")
            return False
    
    def label_data(self, attack_start_time=10.0, attack_end_time=30.0):
        """
        Label data as normal (0) or attack (1) based on time windows
        
        Args:
            attack_start_time: When attack starts (seconds)
            attack_end_time: When attack ends (seconds)
        """
        print(f"\nLabeling data (Attack period: {attack_start_time}s - {attack_end_time}s)...")
        
        if 'time_window_start' not in self.df.columns:
            print("Error: 'time_window_start' column not found!")
            return False
        
        # Label based on time
        self.df['label'] = 0  # Normal
        self.df.loc[
            (self.df['time_window_start'] >= attack_start_time) &
            (self.df['time_window_start'] < attack_end_time),
            'label'
        ] = 1  # Attack
        
        normal_count = (self.df['label'] == 0).sum()
        attack_count = (self.df['label'] == 1).sum()
        
        print(f"Normal windows: {normal_count}")
        print(f"Attack windows: {attack_count}")
        
        if attack_count == 0:
            print("WARNING: No attack windows labeled! Check attack_start_time and attack_end_time")
        
        return True
    
    def prepare_data(self):
        """Prepare features for training"""
        print("\nPreparing data for ML...")
        
        # Select feature columns (exclude time and label)
        exclude_cols = ['time_window_start', 'label']
        self.feature_columns = [col for col in self.df.columns if col not in exclude_cols]
        
        print(f"Using {len(self.feature_columns)} features:")
        for col in self.feature_columns:
            print(f"  - {col}")
        
        X = self.df[self.feature_columns]
        y = self.df['label']
        
        # Handle NaN and inf values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        return X, y
    
    def train_random_forest(self, X, y, test_size=0.3):
        """Train Random Forest classifier"""
        print("\n" + "="*60)
        print("TRAINING RANDOM FOREST CLASSIFIER")
        print("="*60)
        
        # Check if both classes are present
        unique_classes = y.nunique()
        if unique_classes < 2:
            print(f"\n Error: Only {unique_classes} class found in data!")
            print("Cannot train classifier with single class.")
            print("Check your attack time window - no attacks were labeled!")
            return None, None, None  # Return None values

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        print("\nTraining Random Forest...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred = self.model.predict(X_test_scaled)
        
        # Evaluation
        print("\n" + "="*60)
        print("MODEL EVALUATION")
        print("="*60)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        print("\nClassification Report:")
        # Handle case where only one class is in test set
        labels_in_test = sorted(y_test.unique())
        target_names_subset = ['Normal', 'Attack'][:len(labels_in_test)]
        print(classification_report(y_test, y_pred, 
                                    target_names=target_names_subset,
                                    labels=labels_in_test))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        print(f"\nTrue Negatives: {cm[0,0]} | False Positives: {cm[0,1]}")
        print(f"False Negatives: {cm[1,0]} | True Positives: {cm[1,1]}")
        
        # Feature importance
        self._show_feature_importance()
        
        return X_test_scaled, y_test, y_pred
    
    def _show_feature_importance(self):
        """Display feature importance"""
        if self.model is None:
            return
        
        print("\n" + "="*60)
        print("FEATURE IMPORTANCE (Top 10)")
        print("="*60)
        
        importances = self.model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\n" + feature_importance_df.head(10).to_string(index=False))
        
        # Save to file
        feature_importance_df.to_csv('feature_importance.csv', index=False)
        print("\nFull feature importance saved to feature_importance.csv")
    
    def unsupervised_detection(self, X):
        """Use Isolation Forest for unsupervised anomaly detection"""
        print("\n" + "="*60)
        print("UNSUPERVISED ANOMALY DETECTION (Isolation Forest)")
        print("="*60)
        
        # Scale data
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=0.1,  # Expected proportion of outliers
            random_state=42,
            n_jobs=-1
        )
        
        print("\nTraining Isolation Forest...")
        predictions = iso_forest.fit_predict(X_scaled)
        
        # Convert predictions: -1 (anomaly) to 1, 1 (normal) to 0
        anomaly_labels = np.where(predictions == -1, 1, 0)
        
        self.df['anomaly'] = anomaly_labels
        
        anomaly_count = np.sum(anomaly_labels)
        print(f"\nDetected {anomaly_count} anomalous windows ({anomaly_count/len(X)*100:.2f}%)")
        
        # Show anomalous windows
        if anomaly_count > 0:
            print("\nAnomalous time periods:")
            anomalies = self.df[self.df['anomaly'] == 1]
            for idx, row in anomalies.head(20).iterrows():
                print(f"  Time {row['time_window_start']:.1f}s: "
                      f"Ports={row['unique_dst_ports']:.0f}, "
                      f"Packets/s={row['packets_per_second']:.1f}, "
                      f"Diversity={row['port_diversity']:.3f}")
        
        return anomaly_labels
    
    def detect_realtime(self, feature_window):
        """Detect attack in real-time for a single feature window
        \nNOTE: This method is designed for future real-time implementation
          and is not used in the current batch detection workflow.
        """
        if self.model is None:
            print("Error: Model not trained!")
            return None
        
        # Prepare features
        X = pd.DataFrame([feature_window])[self.feature_columns]
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0]
        
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'confidence': max(probability) * 100
        }
    
    def visualize_results(self):
        """Create visualizations"""
        print("\n" + "="*60)
        print("GENERATING VISUALIZATIONS")
        print("="*60)
        
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            fig, axes = plt.subplots(3, 2, figsize=(15, 12))
            
            # Get attack periods (filter by label == 1)
            if 'label' in self.df.columns:
                attack_periods = self.df[self.df['label'] == 1].copy()
                has_attacks = len(attack_periods) > 0
            else:
                has_attacks = False
            
            # Plot 1: Packets per second over time
            ax = axes[0, 0]
            ax.plot(self.df['time_window_start'], self.df['packets_per_second'], 
                    label='Packets/s', linewidth=1)
            if has_attacks:
                ax.scatter(attack_periods['time_window_start'], 
                          attack_periods['packets_per_second'],
                          color='red', label='Attack', s=100, alpha=0.8, zorder=5)
            ax.set_title('Packet Rate Over Time', fontsize=12, fontweight='bold')
            ax.set_xlabel('Time (s)')
            ax.set_ylabel('Packets/s')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Plot 2: Unique destination ports over time
            ax = axes[0, 1]
            ax.plot(self.df['time_window_start'], self.df['unique_dst_ports'], 
                    label='Unique Ports', linewidth=1)
            if has_attacks:
                ax.scatter(attack_periods['time_window_start'], 
                          attack_periods['unique_dst_ports'],
                          color='red', label='Attack', s=100, alpha=0.8, zorder=5)
            ax.set_title('Unique Destination Ports Over Time', fontsize=12, fontweight='bold')
            ax.set_xlabel('Time (s)')
            ax.set_ylabel('Unique Ports')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Plot 3: Port diversity
            ax = axes[1, 0]
            ax.plot(self.df['time_window_start'], self.df['port_diversity'], 
                    label='Port Diversity', linewidth=1)
            if has_attacks:
                ax.scatter(attack_periods['time_window_start'], 
                          attack_periods['port_diversity'],
                          color='red', label='Attack', s=100, alpha=0.8, zorder=5)
            ax.set_title('Port Diversity Over Time', fontsize=12, fontweight='bold')
            ax.set_xlabel('Time (s)')
            ax.set_ylabel('Port Diversity')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Plot 4: SYN/ACK ratio
            ax = axes[1, 1]
            ax.plot(self.df['time_window_start'], self.df['syn_ack_ratio'], 
                    label='SYN/ACK Ratio', linewidth=1)
            if has_attacks:
                ax.scatter(attack_periods['time_window_start'], 
                          attack_periods['syn_ack_ratio'],
                          color='red', label='Attack', s=100, alpha=0.8, zorder=5)
            ax.set_title('SYN/ACK Ratio Over Time', fontsize=12, fontweight='bold')
            ax.set_xlabel('Time (s)')
            ax.set_ylabel('SYN/ACK Ratio')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Plot 5: Protocol distribution
            ax = axes[2, 0]
            protocol_data = self.df[['tcp_ratio', 'udp_ratio', 'icmp_ratio']].mean()
            protocol_data.plot(kind='bar', ax=ax, color=['blue', 'green', 'orange'])
            ax.set_title('Average Protocol Distribution', fontsize=12, fontweight='bold')
            ax.set_ylabel('Ratio')
            ax.set_xticklabels(['TCP', 'UDP', 'ICMP'], rotation=0)
            ax.grid(True, axis='y', alpha=0.3)
            
            # Plot 6: Feature importance (if model trained)
            ax = axes[2, 1]
            if self.model is not None:
                importances = pd.DataFrame({
                    'feature': self.feature_columns,
                    'importance': self.model.feature_importances_
                }).sort_values('importance', ascending=False).head(10)
                
                importances.plot(x='feature', y='importance', kind='barh', ax=ax, legend=False, color='steelblue')
                ax.set_title('Top 10 Feature Importance', fontsize=12, fontweight='bold')
                ax.set_xlabel('Importance')
                ax.grid(True, axis='x', alpha=0.3)
            else:
                ax.text(0.5, 0.5, 'Model not trained', ha='center', va='center', fontsize=14)
                ax.set_title('Feature Importance', fontsize=12, fontweight='bold')
            
            plt.tight_layout()
            plt.savefig('detection_results.png', dpi=150, bbox_inches='tight')
            print("\nVisualizations saved to detection_results.png")
            
        except Exception as e:
            print(f"Error creating visualizations: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Main detection pipeline"""
    if len(sys.argv) < 2:
        print("Usage: python traffic_detector.py <features_file> [attack_start_time] [attack_end_time]")
        print("\nExample:")
        print("  python traffic_detector.py /tmp/h1_features.csv 20 30")
        print("\nThis will:")
        print("  1. Load features from CSV")
        print("  2. Label data (attack from 20s to 30s)")
        print("  3. Train Random Forest classifier")
        print("  4. Perform unsupervised anomaly detection")
        print("  5. Generate visualizations")
        sys.exit(1)
    
    features_file = sys.argv[1]
    attack_start = float(sys.argv[2]) if len(sys.argv) > 2 else 95.0
    attack_end = float(sys.argv[3]) if len(sys.argv) > 3 else 97.0
    
    print("\n" + "="*60)
    print("AI-BASED PORT SCAN ATTACK DETECTOR")
    print("="*60)
    print(f"\nFeatures file: {features_file}")
    print(f"Attack period: {attack_start}s - {attack_end}s")
    
    # Create detector
    detector = PortScanDetector(features_file)
    
    # Load features
    if not detector.load_features():
        sys.exit(1)
    
    # Label data
    if not detector.label_data(attack_start, attack_end):
        sys.exit(1)
    
    # Prepare data
    X, y = detector.prepare_data()
    
    # Train supervised model
    result = detector.train_random_forest(X, y)
    
    # Check if training succeeded
    if result[0] is None:
        print("\nSkipping supervised detection due to insufficient class diversity")
        print("Continuing with unsupervised detection only...\n")
    else:
        X_test, y_test, y_pred = result
    
    # Unsupervised detection
    anomaly_labels = detector.unsupervised_detection(X)
    
    # Visualize
    detector.visualize_results()
    
    print("\n" + "="*60)
    print("DETECTION COMPLETE!")
    print("="*60)
    print("\nOutput files:")
    print("  - feature_importance.csv: Feature importance rankings")
    print("  - detection_results.png: Visualization plots")
    print("\n  Port scan attack detection completed successfully!")


if __name__ == '__main__':
    main()
