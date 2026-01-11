#!/usr/bin/env python3
"""
Port Scanning Attack Scenario with AI-based Detection
Network Security Project - Mininet-based attack simulation
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, OVSController
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
import time
import os
import subprocess

class PortScanTopology(Topo):
    """Custom topology for port scanning attack demonstration
    
    Topology:
        h1 (victim server) --- s1 --- h2 (legitimate client)
                                |
                               h3 (attacker)
    """
    
    def build(self):
        # Add hosts
        h1 = self.addHost('h1', cpu=0.5)  # Victim server
        h2 = self.addHost('h2', cpu=0.5)  # Legitimate client
        h3 = self.addHost('h3', cpu=0.5)  # Attacker
        
        # Add switch
        s1 = self.addSwitch('s1')
        
        # Add links with bandwidth and delay constraints
        self.addLink(h1, s1, bw=10, delay='5ms', max_queue_size=1000, use_htb=True)
        self.addLink(h2, s1, bw=10, delay='5ms', max_queue_size=1000, use_htb=True)
        self.addLink(h3, s1, bw=10, delay='5ms', max_queue_size=1000, use_htb=True)


def generate_attack_traffic(net):
    """Prepare port scanning attack using nmap"""
    print("\n=== Preparing Port Scanning Attack ===")
    
    h3 = net.get('h3')
    h1 = net.get('h1')
    h1_ip = h1.IP()
    
    print(f"Target: {h1_ip}")
    print("Attack type: TCP SYN scan on ports 1-1000")
    
    return h1_ip


def start_victim_services(net):
    """Start services on victim"""
    print("\n=== Starting Services on Victim (h1) ===")
    h1 = net.get('h1')
    
    print("Starting HTTP server on port 80...")
    h1.cmd('python3 -m http.server 80 > /tmp/h1_http.log 2>&1 &')
    
    print("Starting iperf server on port 5001...")
    h1.cmd('iperf -s > /tmp/h1_iperf.log 2>&1 &')
    
    # Start listeners on some common ports to respond to scans
    print("Starting listeners on common ports...")
    for port in [22, 443, 3306, 8080]:
        h1.cmd(f'nc -l -p {port} > /dev/null 2>&1 &')
    
    time.sleep(2)
    print("Services started on h1")


def start_legitimate_traffic(net):
    """Start legitimate traffic from h2"""
    print("\n=== Starting Legitimate Traffic (h2 -> h1) ===")
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1_ip = h1.IP()
    
    print("h2 making periodic HTTP requests...")
    h2.cmd(f'while true; do wget -q -O /dev/null http://{h1_ip}/ 2>/dev/null; sleep 3; done &')
    
    print("h2 starting iperf client...")
    h2.cmd(f'iperf -c {h1_ip} -t 300 > /tmp/h2_iperf.log 2>&1 &')
    
    time.sleep(2)


def start_traffic_capture(net):
    """Start tcpdump on all hosts"""
    print("\n=== Starting Traffic Capture ===")
    
    for host_name in ['h1', 'h2', 'h3']:
        host = net.get(host_name)
        iface = host.defaultIntf().name
        pcap_file = f'/tmp/{host_name}.pcap'
        
        print(f"Capturing on {host_name} ({iface}) -> {pcap_file}")
        host.cmd(f'tcpdump -i {iface} -w {pcap_file} > /dev/null 2>&1 &')
    
    time.sleep(2)


def execute_port_scan_attack(net, target_ip):
    """Execute port scan using nmap"""
    print("\n=== EXECUTING PORT SCAN ATTACK ===")
    h3 = net.get('h3')
    
    print(f"Scanning ports 1-1000 on {target_ip}...")
    print("Using nmap SYN scan (stealth scan)...")
    
    # Run nmap scan - this will actually send SYN packets to 1000 ports
    result = h3.cmd(f'nmap -sS -p 1-1000 -T4 --min-rate 50 --max-retries 0 {target_ip} > /tmp/nmap_output.txt 2>&1')
    
    # Show nmap results
    nmap_output = h3.cmd('cat /tmp/nmap_output.txt')
    print("\nNmap scan results:")
    print(nmap_output[:500])  # First 500 chars
    
    print("\nPort scan attack completed!")


def stop_all_processes(net):
    """Stop all background processes"""
    print("\n=== Stopping All Processes ===")
    
    for host_name in ['h1', 'h2', 'h3']:
        host = net.get(host_name)
        host.cmd('pkill -f tcpdump')
        host.cmd('pkill -f iperf')
        host.cmd('pkill -f wget')
        host.cmd('pkill -f nc')
        host.cmd('pkill -f "http.server"')
        host.cmd('pkill -f nmap')
    
    print("All processes stopped")


def export_to_csv(pcap_file, csv_file):
    """Convert pcap to CSV using tshark"""
    print(f"\nExporting {pcap_file} to {csv_file}...")
    
    fields = [
        'frame.time_relative',
        'frame.len',
        'eth.src',
        'eth.dst',
        'ip.src',
        'ip.dst',
        'ip.proto',
        'tcp.srcport',
        'tcp.dstport',
        'tcp.flags',
        'tcp.flags.syn',
        'tcp.flags.ack',
        'tcp.flags.fin',
        'tcp.flags.reset',
        'udp.srcport',
        'udp.dstport',
        'icmp.type'
    ]
    
    fields_str = ' -e '.join([''] + fields)
    cmd = f'tshark -r {pcap_file} -T fields {fields_str} -E header=y -E separator=, -E quote=d -E occurrence=f > {csv_file}'
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        size = os.path.getsize(csv_file)
        print(f"Successfully exported to {csv_file} ({size:,} bytes)")
    else:
        print(f" Error exporting: {result.stderr}")


def run_experiment():
    """Main experiment runner"""
    print("\n" + "="*60)
    print("PORT SCANNING ATTACK SIMULATION WITH AI DETECTION")
    print("="*60)
    
    # Clean up
    os.system('sudo mn -c > /dev/null 2>&1')
    
    # Create topology and network
    topo = PortScanTopology()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=OVSController)
    net.start()
    
    print("\n=== Network Topology ===")
    dumpNodeConnections(net.hosts)
    
    # Test connectivity
    print("\n=== Testing Network Connectivity ===")
    net.pingAll()
    
    try:
        # Step 1: Prepare attack
        target_ip = generate_attack_traffic(net)
        time.sleep(2)
        
        # Step 2: Start victim services
        start_victim_services(net)
        
        # Step 3: Start traffic capture
        start_traffic_capture(net)
        
        # Step 4: Start legitimate traffic
        start_legitimate_traffic(net)
        
        # Normal traffic phase
        print("\n=== Normal Traffic Phase (80 seconds) ===")
        for i in range(80, 0, -1):
            print(f"  {i} seconds...", end='\r')
            time.sleep(1)
        print()
        
        # Step 5: Execute attack
        execute_port_scan_attack(net, target_ip)
        
        # Wait a bit after attack
        print("\n=== Attack Completion Phase (30 seconds) ===")
        for i in range(30, 0, -1):
            print(f" {i} seconds...", end='\r')
            time.sleep(1)
        print()
        
        # Continue normal traffic
        print("\n=== Post-Attack Normal Traffic (80 seconds) ===")
        for i in range(80, 0, -1):
            print(f"  {i} seconds...", end='\r')
            time.sleep(1)
        print()
        
        # Step 6: Stop all processes
        stop_all_processes(net)
        
        # Wait for captures to flush
        print("\nWaiting for packet captures to complete...")
        time.sleep(10)
        
        # Step 7: Export to CSV
        print("\n=== Exporting Captures to CSV ===")
        for host_name in ['h1', 'h2', 'h3']:
            pcap_file = f'/tmp/{host_name}.pcap'
            csv_file = f'/tmp/{host_name}.csv'
            if os.path.exists(pcap_file):
                export_to_csv(pcap_file, csv_file)
        
        print("\n" + "="*60)
        print("EXPERIMENT COMPLETED!")
        print("="*60)
        print("\nGenerated files:")
        for f in ['/tmp/h1.csv', '/tmp/h2.csv', '/tmp/h3.csv']:
            if os.path.exists(f):
                size = os.path.getsize(f)
                print(f"  OK {f} ({size:,} bytes)")
        
        print("\nNext steps:")
        print("  1. python3 feature_extraction.py /tmp/h1.csv /tmp/h1_features.csv 1.0")
        print("  2. python3 traffic_detector.py /tmp/h1_features.csv 20 30")
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        stop_all_processes(net)
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()
