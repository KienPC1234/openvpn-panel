# Premium VPN Manager System

An open-source OpenVPN user management system with a modern interface, integrated WebPush notifications, email OTP verification, and an automatic locking mechanism for expired users.

## 🚀 Key Features

- **User Management:**
  - Automatic expiry calculation based on purchase date and duration.
  - **Grace Period (3 days)**: Users can stay connected for an extra 3 days after expiry before being fully locked.
  - Automatic **3-day Demo bonus** for newly registered users.
  - Instant Lock/Unlock through Firewall (iptables/nftables).
- **Secure Authentication:**
  - Email OTP verification required for registration.
  - Password reset via OTP.
  - Automatic Captive Portal detection and redirection for locked users.
- **Notification System:**
  - WebPush Notifications: Alerts for upcoming expiry, lock, and unlock events on Desktop/Mobile.
  - Email Notifications: Automated renewal reminders.
- **Admin Dashboard:**
  - Powered by the premium **Unfold** theme.
  - Real-time logging for 4 services (OpenVPN, Panel, Worker, Beat) directly in the browser.
  - Real-time traffic monitoring and connection status.

## 🛠️ Tech Stack

- **Backend:** Django 6.0 (Python 3.12+)
- **VPN Engine:** OpenVPN
- **Database:** SQLite3 / Redis (Cache & Celery Broker)
- **Task Queue:** Celery & Celery Beat
- **Frontend:** Tailwind CSS, HTMX, Alpine.js
- **Process Manager:** Supervisor

## 📦 Installation Guide

### 1. Environment Setup
Ensure Python 3.12+ and Redis are installed.
```bash
# Clone project
git clone <repository_url>
cd openvpn-panel

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Edit `vpn_project/settings.py`:
- `EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`: For OTP delivery.
- `WEBPUSH_SETTINGS`: VAPID keys for push notifications.
- `VPN_SETTINGS`: Paths for OpenVPN logs and gateway.

### 3. Initialization
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 4. Build Assets
```bash
python manage.py tailwind build
python manage.py collectstatic --no-input
```

## 🛠️ Service Management (Supervisor)

For production stability, use Supervisor to manage the 3 background processes. See [supervisor_sample.conf](./supervisor_sample.conf) for details.

### Fast Deploy Command
Use the provided script for updates:
```bash
bash deploy.sh
```

## 📝 Troubleshooting

- **Logs:** Check `/data/openvpn/app.log` or the Admin interface logs.
- **VPN:** Check service status: `systemctl status openvpn-server@server`.
- **Celery:** Verify redis is running: `redis-cli ping`.

---
*Developed by KienPC.*
