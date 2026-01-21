# Windows Setup Guide for Port Scan Attack Detection Project

## Important Note for Windows Users

⚠️ **Mininet requires Linux!** It cannot run natively on Windows.

You have **3 options**:

---

## Option 1: WSL2 (Explored but in the end not working)

Windows Subsystem for Linux 2 allows you to run Linux directly on Windows.

### Step 1: Install WSL2

```powershell
# Open PowerShell as Administrator and run:
wsl --install -d Ubuntu

# Restart your computer
```

### Step 2: Install Dependencies in WSL2

```bash
# Open Ubuntu from Start Menu
# Update packages
sudo apt-get update
sudo apt-get upgrade -y

# Install Mininet and tools
sudo apt-get install -y mininet tcpdump tshark iperf tcpreplay

# Install Python packages
sudo apt-get install -y python3-pip
pip3 install -r requirements.txt
```

### Step 3: Access Your Files

```bash
# Your Windows files are in /mnt/
cd /mnt/e/school/Masterat/AI\ in\ sisteme\ de\ securitate\ informatica/Proiect1/

# Run the project
sudo python3 port_scan_attack.py
```
---

## Option 3: Mininet Pre-built VM (Used for this project)

### Step 1: Download Mininet VM
- https://github.com/mininet/mininet/releases/
- Download: mininet-2.3.0-210211-ubuntu-20.04.1-legacy-server-amd64.zip

### Step 2: Import to VirtualBox
1. Extract the .ovf file
2. VirtualBox → File → Import Appliance
3. Select the .ovf file

### Step 3: Login
- Username: `mininet`
- Password: `mininet`

### Step 4: Install Additional Packages
```bash
sudo apt-get update
sudo apt-get install -y tcpreplay tshark python3-pip
pip3 install pandas numpy scikit-learn matplotlib seaborn scapy
```

---

## Testing Setup

Once you have Linux running:

```bash
# Test Mininet
sudo mn --test pingall

# Test Python packages
python3 test_system.py

# Run the experiment
sudo python3 port_scan_attack.py
```

---

## Accessing Results on Windows

### From WSL2:
```bash
# Copy results to Windows
cp detection_results.png /mnt/c/Users/YourUsername/Desktop/
cp feature_importance.csv /mnt/c/Users/YourUsername/Desktop/
```

### From VirtualBox:
- Set up Shared Folders
- Or use SCP/SFTP to copy files

---