# OpenVPN Web Manager

A robust and simple toolset for managing OpenVPN Servers. It includes an automated installation script (forked from Nyr) and a modern Web Dashboard for managing users, configurations, and system services.

## Key Features

*   **Automated OpenVPN Installation**: Bash script to set up a fully functional OpenVPN Server in minutes.
*   **Web Dashboard**: Intuitive and responsive interface for easy management.
*   **User Management**: Add, delete, lock/unlock users, and generate OTPs for secure configuration downloads.
*   **Real-time Monitoring**: View active connections, bandwidth usage, and system logs in real-time via WebSockets.
*   **System Management**: Check service status, restart OpenVPN service, view logs, and monitor network interfaces.
*   **Configuration Editor**: Edit `server.conf` and client templates directly from the web interface.

---

## Prerequisites

*   **Operating System**: Linux (Ubuntu, Debian, CentOS, Fedora, etc.)
*   **Python**: Version 3.10 or higher
*   **Permissions**: Root privileges (`sudo`) are required for both installation and running the web panel.

---

## 1. Install OpenVPN Server

Use the included `openvpn-install.sh` script to install and configure OpenVPN.

```bash
# Grant execution permissions
chmod +x openvpn-install.sh

# Run the installer (requires root)
sudo ./openvpn-install.sh
```

Follow the on-screen instructions to select your protocol (UDP/TCP), port, and DNS settings. Once completed, the first client configuration file will be generated.

**Note:** This script installs `easy-rsa` at `/etc/openvpn/server/easy-rsa`. The web panel relies on this path to manage certificates.

---

## 2. Install Web Panel Environment

You can set up the Python environment using either `pip` or `conda`.

### Option 1: Using Pip (Recommended)
```bash
# Install required Python packages
pip install fastapi uvicorn[standard] jinja2 python-multipart ujson requests aiofiles
```

### Option 2: Using Conda
```bash
# Create and activate environment from file
conda env create -f environment.yml
conda activate vpn_panel
```

---

## 3. Configuration

1.  **Create the configuration file**:
    Copy the example config file to `config.ini`:
    ```bash
    cp config.ini.example config.ini
    ```

2.  **Edit `config.ini`**:
    Update the file with your specific settings:

    ```ini
    [Security]
    # Admin password for the web dashboard login
    admin_password = your_secure_password
    # Secret key for session cookies (generate a long random string)
    secret_key = change_this_to_a_random_secret_string

    [Paths]
    # Output directory for generated .ovpn files
    ovpn_out_dir = ovpn/
    
    # Path to EasyRSA (Default from the install script)
    easy_rsa_dir = /etc/openvpn/server/easy-rsa
    
    # Client template file (appended to client configs)
    client_common = /etc/openvpn/server/client-common.txt
    
    # OpenVPN static IP persistence file
    ipp_file = /etc/openvpn/server/ipp.txt

    [Network]
    # VPN Server IP or Domain (used for user locking features)
    vpn_gateway = 10.8.0.1
    # Web portal port (if using captive portal features)
    portal_port = 8000
    # Support link (displayed to users when locked/error)
    mess_link = https://m.me/your_support
    ```

---

## 4. Deploy with Supervisor (Production)

To ensure the Web Panel runs continuously and restarts automatically on failure, use `supervisor`.

### 4.1. Install Supervisor

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install supervisor -y

# CentOS/RHEL
sudo yum install supervisor -y
```

### 4.2. Create Configuration File

Create a config file at `/etc/supervisor/conf.d/vpn_panel.conf` (Ubuntu/Debian) or `/etc/supervisord.d/vpn_panel.ini` (CentOS).

**Important:** Replace `/data/openvpn` with the actual path to your project.

```ini
[program:vpn_panel]
directory=/data/openvpn
command=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
user=root
autostart=true
autorestart=true
stderr_logfile=/var/log/vpn_panel.err.log
stdout_logfile=/var/log/vpn_panel.out.log
environment=LANG=en_US.UTF-8,LC_ALL=en_US.UTF-8
```

*Note: If using a virtual environment (venv/conda), replace `/usr/bin/python3` with the full path to the python executable inside your environment.*

### 4.3. Start the Service

```bash
# Reload supervisor configuration
sudo supervisorctl reread
sudo supervisorctl update

# Start the VPN Panel
sudo supervisorctl start vpn_panel

# Check status
sudo supervisorctl status
```

---

## 5. Usage Guide

1.  **Access**: Open your browser and navigate to `http://<YOUR_SERVER_IP>:8000`.
2.  **Login**: Use the password defined in `config.ini`.
3.  **Dashboard Sections**:
    *   **Dashboard**: Overview of total users, active connections, and network traffic graph.
    *   **User Management**: Add new users, download configurations via OTP, and lock/unlock access.
    *   **Settings**: Edit `server.conf` and client templates.
    *   **Logs**: View real-time system logs for debugging.

### Security Note
The application must run as **ROOT** (`user=root` in supervisor) to manage OpenVPN files (`/etc/openvpn`), execute `iptables` rules, and control system services via `systemctl`. 
**Security Warning:** It is highly recommended to restrict access to port 8000 using a Firewall (UFW/IPTables) or allow access only via a VPN connection.

---

## Directory Structure

```
/data/openvpn/
├── main.py              # Main Application (FastAPI)
├── openvpn-install.sh   # OpenVPN Installer Script (Bash)
├── config.ini           # Configuration File
├── templates/           # HTML Templates (Jinja2)
├── static/              # Static Assets (CSS, JS, MSI Installer)
└── ovpn/                # Directory for generated .ovpn files
```
