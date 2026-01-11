#!/bin/bash

echo "=== Testing Mininet Setup ==="

echo -n "Checking Mininet... "
if command -v mn &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking OVS... "
if command -v ovs-vsctl &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking tcpdump... "
if command -v tcpdump &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking tshark... "
if command -v tshark &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking scapy... "
if python3 -c "import scapy.all" &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking sklearn... "
if python3 -c "import sklearn" &> /dev/null; then
    echo "✓ Installed"
else
    echo "✗ Not found"
fi

echo -n "Checking OVS kernel module... "
if lsmod | grep openvswitch &> /dev/null; then
    echo "✓ Loaded"
else
    echo "✗ Not loaded - run: sudo modprobe openvswitch"
fi

echo ""
echo "=== Testing Mininet ==="
sudo mn --test pingall
