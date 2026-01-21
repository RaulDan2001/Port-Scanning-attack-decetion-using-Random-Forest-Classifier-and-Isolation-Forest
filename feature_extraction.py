#!/usr/bin/env python3
"""
Feature Extraction from Network Traffic
Extracts meaningful features for AI-based attack detection
"""

import pandas as pd
import numpy as np
from collections import defaultdict
import sys


class TrafficFeatureExtractor:
    """Extract features from network traffic CSV files"""
    
    def __init__(self, csv_file, window_size=1.0):
        """
        Initialize feature extractor
        
        Args:
            csv_file: Path to CSV file exported from pcap
            window_size: Time window in seconds for feature aggregation
        """
        self.csv_file = csv_file
        self.window_size = window_size
        self.df = None
        
    def load_data(self):
        """Load CSV data"""
        print(f"Loading {self.csv_file}...")
        try:
            self.df = pd.read_csv(self.csv_file)
            print(f"Loaded {len(self.df)} packets")
            
            # Clean column names (remove quotes if present)
            self.df.columns = self.df.columns.str.strip().str.replace('"', '')
            
            # Convert time to float
            if 'frame.time_relative' in self.df.columns:
                self.df['frame.time_relative'] = pd.to_numeric(
                    self.df['frame.time_relative'], errors='coerce'
                )
            
            # Convert port columns to numeric, handling empty values
            for port_col in ['tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']:
                if port_col in self.df.columns:
                    # Replace empty strings with NaN, then convert to numeric
                    self.df[port_col] = pd.to_numeric(
                        self.df[port_col].replace('', np.nan), 
                        errors='coerce'
                    )
            
            # Convert TCP flags to numeric (1/0)
            for flag_col in ['tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset']:
                if flag_col in self.df.columns:
                    self.df[flag_col] = pd.to_numeric(
                        self.df[flag_col].replace('', 0), 
                        errors='coerce'
                    ).fillna(0)
            
            # DEBUG: Print port statistics
            if 'tcp.dstport' in self.df.columns:
                valid_ports = self.df['tcp.dstport'].dropna()
                unique_ports = valid_ports.nunique()
                print(f"DEBUG: Found {len(valid_ports)} packets with TCP dst ports")
                print(f"DEBUG: {unique_ports} unique destination ports")
                if unique_ports > 0 and unique_ports < 20:
                    print(f"DEBUG: Port list: {sorted(valid_ports.unique())}")
            
            return True
        except Exception as e:
            print(f"Error loading CSV: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def extract_features(self):
        """Extract features in time windows"""
        if self.df is None or len(self.df) == 0:
            print("No data loaded!")
            return None
        
        print(f"\nExtracting features with {self.window_size}s time windows...")
        
        # Get time range
        if 'frame.time_relative' not in self.df.columns:
            print("Error: 'frame.time_relative' column not found!")
            return None
        
        max_time = self.df['frame.time_relative'].max()
        min_time = self.df['frame.time_relative'].min()
        
        if pd.isna(max_time) or pd.isna(min_time):
            print("Error: Invalid time values in data")
            return None
        
        print(f"Time range: {min_time:.2f}s to {max_time:.2f}s")
        
        # Create time windows
        num_windows = int(np.ceil((max_time - min_time) / self.window_size))
        print(f"Creating {num_windows} time windows...")
        
        features_list = []
        
        for i in range(num_windows):
            window_start = min_time + i * self.window_size
            window_end = window_start + self.window_size
            
            # Get packets in this window
            window_df = self.df[
                (self.df['frame.time_relative'] >= window_start) &
                (self.df['frame.time_relative'] < window_end)
            ]
            
            if len(window_df) == 0:
                continue
            
            # Extract features for this window
            features = self._extract_window_features(window_df, window_start)
            features_list.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        print(f"\nExtracted {len(features_df)} feature windows")
        print(f"Features: {list(features_df.columns)}")
        
        return features_df
    
    def _extract_window_features(self, window_df, window_start):
        """Extract features for a single time window """
        features = {
            'time_window_start': window_start,
            'total_packets': len(window_df),
            'total_bytes': window_df['frame.len'].sum() if 'frame.len' in window_df.columns else 0,
        }
        
        # Packet rate
        features['packets_per_second'] = len(window_df) / self.window_size
        features['bytes_per_second'] = features['total_bytes'] / self.window_size
        
        # Average packet size
        if len(window_df) > 0 and 'frame.len' in window_df.columns:
            features['avg_packet_size'] = window_df['frame.len'].mean()
            features['std_packet_size'] = window_df['frame.len'].std()
            if pd.isna(features['std_packet_size']):
                features['std_packet_size'] = 0
        else:
            features['avg_packet_size'] = 0
            features['std_packet_size'] = 0
        
        # Protocol distribution - Check ip.proto OR presence of port columns
        tcp_df = pd.DataFrame()
        udp_df = pd.DataFrame()
        
        # Method 1: Use ip.proto if available
        if 'ip.proto' in window_df.columns:
            proto_str = window_df['ip.proto'].astype(str)
            tcp_by_proto = window_df[proto_str == '6'].copy()
            udp_by_proto = window_df[proto_str == '17'].copy()
            icmp_by_proto = window_df[proto_str == '1'].copy()
            
            tcp_count = len(tcp_by_proto)
            udp_count = len(udp_by_proto)
            icmp_count = len(icmp_by_proto)
        else:
            tcp_count = 0
            udp_count = 0
            icmp_count = 0
        
        # Method 2: FALLBACK - Detect TCP by presence of tcp.srcport or tcp.dstport
        if 'tcp.srcport' in window_df.columns or 'tcp.dstport' in window_df.columns:
            has_tcp_port = (
                (window_df['tcp.srcport'].notna() if 'tcp.srcport' in window_df.columns else False) |
                (window_df['tcp.dstport'].notna() if 'tcp.dstport' in window_df.columns else False)
            )
            tcp_df = window_df[has_tcp_port].copy()
            
            # If we found TCP packets this way but not via ip.proto, use this count
            if len(tcp_df) > tcp_count:
                tcp_count = len(tcp_df)
        else:
            # Use the proto-based version
            if 'ip.proto' in window_df.columns:
                tcp_df = tcp_by_proto
        
        # Similar fallback for UDP
        if 'udp.srcport' in window_df.columns or 'udp.dstport' in window_df.columns:
            has_udp_port = (
                (window_df['udp.srcport'].notna() if 'udp.srcport' in window_df.columns else False) |
                (window_df['udp.dstport'].notna() if 'udp.dstport' in window_df.columns else False)
            )
            udp_df = window_df[has_udp_port].copy()
            
            if len(udp_df) > udp_count:
                udp_count = len(udp_df)
        
        # Calculate ratios
        total = len(window_df)
        features['tcp_ratio'] = tcp_count / total if total > 0 else 0
        features['udp_ratio'] = udp_count / total if total > 0 else 0
        features['icmp_ratio'] = icmp_count / total if total > 0 else 0
        
        # DEBUG: Print for attack windows
        if window_start >= 80.0 and window_start <= 110.0:
            print(f"  DEBUG Window {window_start:.1f}s: Total={len(window_df)}, TCP={len(tcp_df)}")
            if len(tcp_df) > 0 and 'tcp.dstport' in tcp_df.columns:
                unique = tcp_df['tcp.dstport'].dropna().nunique()
                print(f"    -> {unique} unique dst ports")
        
        if len(tcp_df) > 0:
            # TCP flags
            features['syn_count'] = int(tcp_df['tcp.flags.syn'].sum()) if 'tcp.flags.syn' in tcp_df.columns else 0
            features['ack_count'] = int(tcp_df['tcp.flags.ack'].sum()) if 'tcp.flags.ack' in tcp_df.columns else 0
            features['fin_count'] = int(tcp_df['tcp.flags.fin'].sum()) if 'tcp.flags.fin' in tcp_df.columns else 0
            features['rst_count'] = int(tcp_df['tcp.flags.reset'].sum()) if 'tcp.flags.reset' in tcp_df.columns else 0
            
            # SYN/ACK ratio
            features['syn_ack_ratio'] = (features['syn_count'] / features['ack_count'] 
                                         if features['ack_count'] > 0 else features['syn_count'])
            
            # Port scanning features
            tcp_dst_ports = []
            udp_dst_ports = []
            
            # Extract TCP destination ports
            if 'tcp.dstport' in tcp_df.columns:
                valid_tcp_ports = tcp_df['tcp.dstport'].dropna()
                tcp_dst_ports = valid_tcp_ports[valid_tcp_ports > 0].astype(int).tolist()
            
            # Extract UDP destination ports
            if len(udp_df) > 0 and 'udp.dstport' in udp_df.columns:
                valid_udp_ports = udp_df['udp.dstport'].dropna()
                udp_dst_ports = valid_udp_ports[valid_udp_ports > 0].astype(int).tolist()
            
            # Combine all destination ports
            all_dst_ports = tcp_dst_ports + udp_dst_ports
            
            # Unique destination ports
            unique_dst_ports = len(set(all_dst_ports)) if all_dst_ports else 0
            features['unique_dst_ports'] = unique_dst_ports
            
            # Port diversity (Shannon entropy)
            if unique_dst_ports > 0 and len(all_dst_ports) > 0:
                port_counts = pd.Series(all_dst_ports).value_counts()
                probabilities = port_counts / len(all_dst_ports)
                entropy = -sum(probabilities * np.log2(probabilities + 1e-10))
                max_entropy = np.log2(unique_dst_ports) if unique_dst_ports > 1 else 1
                port_diversity = entropy / max_entropy if max_entropy > 0 else 0
                features['port_diversity'] = port_diversity
            else:
                features['port_diversity'] = 0.0
            
            # Alert if port scan detected
            if unique_dst_ports > 100:
                print(f"    Window {window_start:.1f}s: {unique_dst_ports} unique ports (PORT SCAN!)")
            elif unique_dst_ports > 50:
                print(f"   Window {window_start:.1f}s: {unique_dst_ports} unique ports")
            
            # Unique IPs
            if 'ip.src' in tcp_df.columns:
                features['unique_src_ips'] = tcp_df['ip.src'].dropna().nunique()
            else:
                features['unique_src_ips'] = 0
            
            if 'ip.dst' in tcp_df.columns:
                features['unique_dst_ips'] = tcp_df['ip.dst'].dropna().nunique()
            else:
                features['unique_dst_ips'] = 0
        else:
            # No TCP packets
            features['syn_count'] = 0
            features['ack_count'] = 0
            features['fin_count'] = 0
            features['rst_count'] = 0
            features['syn_ack_ratio'] = 0
            features['unique_dst_ports'] = 0
            features['port_diversity'] = 0
            features['unique_src_ips'] = 0
            features['unique_dst_ips'] = 0
        
        # Connection patterns
        if 'ip.src' in window_df.columns and 'ip.dst' in window_df.columns:
            connections = window_df[['ip.src', 'ip.dst']].dropna()
            features['unique_connections'] = len(connections.drop_duplicates())
        else:
            features['unique_connections'] = 0
        
        return features
    
    def save_features(self, features_df, output_file):
        """Save extracted features to CSV"""
        if features_df is not None:
            features_df.to_csv(output_file, index=False)
            print(f"\nFeatures saved to {output_file}")
            print(f"Shape: {features_df.shape}")
            
            # Save sample for inspection
            print("\nFirst 5 feature windows:")
            print(features_df.head().to_string())
            
            return True
        return False
    
    def print_summary(self, features_df):
        """Print summary statistics"""
        if features_df is None or len(features_df) == 0:
            print("No features to summarize")
            return
        
        print("\n" + "="*60)
        print("FEATURE SUMMARY")
        print("="*60)
        print(f"\nNumber of time windows: {len(features_df)}")
        print(f"\nKey statistics:")
        print(f"  Packets/sec - Mean: {features_df['packets_per_second'].mean():.2f}, "
              f"Max: {features_df['packets_per_second'].max():.2f}")
        print(f"  Unique ports - Mean: {features_df['unique_dst_ports'].mean():.2f}, "
              f"Max: {features_df['unique_dst_ports'].max():.0f}")
        print(f"  Port diversity - Mean: {features_df['port_diversity'].mean():.4f}, "
              f"Max: {features_df['port_diversity'].max():.4f}")
        print(f"  SYN/ACK ratio - Mean: {features_df['syn_ack_ratio'].mean():.2f}, "
              f"Max: {features_df['syn_ack_ratio'].max():.2f}")
        
        # Detect potential attack windows
        print("\n" + "="*60)
        print("POTENTIAL ATTACK DETECTION (Threshold-based)")
        print("="*60)
        
        # Simple threshold detection
        attack_indicators = (
            (features_df['unique_dst_ports'] > 100) |  # Many different ports
            (features_df['port_diversity'] > 1500) |    # High port diversity
            (features_df['syn_ack_ratio'] > 0.3)         # Many unanswered SYNs
        )
        
        attack_windows = features_df[attack_indicators]
        
        if len(attack_windows) > 0:
            print(f"\n WARNING: {len(attack_windows)} suspicious windows detected!")
            print(f"\nSuspicious time periods:")
            for idx, row in attack_windows.iterrows():
                print(f"  Time {row['time_window_start']:.1f}s: "
                      f"Ports={row['unique_dst_ports']:.0f}, "
                      f"Diversity={row['port_diversity']:.3f}, "
                      f"SYN/ACK={row['syn_ack_ratio']:.2f}")
            
            # Show time range of attacks
            attack_start = attack_windows['time_window_start'].min()
            attack_end = attack_windows['time_window_start'].max()
            print(f"\nAttack time range: {attack_start:.1f}s to {attack_end:.1f}s")
        else:
            print("\nNo obvious attack patterns detected with simple thresholds")
            print("  (This is normal if only legitimate traffic was captured)")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python feature_extraction.py <csv_file> [output_file] [window_size]")
        print("\nExample:")
        print("  python feature_extraction.py /tmp/h1.csv /tmp/h1_features.csv 1.0")
        print("  python feature_extraction.py h1.csv h1_features.csv 1.0")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else csv_file.replace('.csv', '_features.csv')
    window_size = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    
    print("="*60)
    print("NETWORK TRAFFIC FEATURE EXTRACTION")
    print("="*60)
    print(f"Input file: {csv_file}")
    print(f"Output file: {output_file}")
    print(f"Window size: {window_size}s")
    print("="*60)
    
    # Extract features
    extractor = TrafficFeatureExtractor(csv_file, window_size=window_size)
    
    if not extractor.load_data():
        sys.exit(1)
    
    features_df = extractor.extract_features()
    
    if features_df is not None:
        extractor.save_features(features_df, output_file)
        extractor.print_summary(features_df)
        
        print("\n" + "="*60)
        print("Feature extraction completed successfully!")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("Feature extraction failed!")
        print("="*60)
        sys.exit(1)


if __name__ == '__main__':
    main()
