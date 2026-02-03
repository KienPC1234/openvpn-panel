# OpenVPN Web Manager

Một bộ công cụ quản lý OpenVPN Server đơn giản và mạnh mẽ, bao gồm script cài đặt tự động (fork từ Nyr) và giao diện Web Dashboard hiện đại để quản lý người dùng, cấu hình và dịch vụ.

## Tính năng

*   **Tự động cài đặt OpenVPN**: Script Bash giúp cài đặt OpenVPN Server chỉ trong vài phút.
*   **Web Dashboard**: Giao diện trực quan để quản lý.
*   **Quản lý User**: Thêm, xóa, khóa/mở khóa, tạo mã OTP tải file cấu hình.
*   **Quản lý Hệ thống**: Xem trạng thái service, restart service, xem log OpenVPN, xem thông tin card mạng.
*   **Chỉnh sửa Cấu hình**: Sửa file `server.conf` và template client trực tiếp trên web.

---

## 1. Cài đặt OpenVPN Server

Sử dụng script `openvpn-install.sh` có sẵn trong thư mục để cài đặt OpenVPN.

```bash
# Cấp quyền thực thi
chmod +x openvpn-install.sh

# Chạy script cài đặt (yêu cầu quyền root)
sudo ./openvpn-install.sh
```

Làm theo các hướng dẫn trên màn hình (chọn protocol, port, DNS...). Sau khi cài đặt xong, file cấu hình user đầu tiên sẽ được tạo.

**Lưu ý:** Script này cũng cài đặt `easy-rsa` tại `/etc/openvpn/server/easy-rsa`. Web panel sẽ sử dụng đường dẫn này để quản lý chứng chỉ.

---

## 2. Cài đặt Web Panel

### Yêu cầu
*   Python 3.10+
*   Pip hoặc Conda

### Cài đặt thư viện
Bạn có thể cài đặt môi trường thông qua `conda` hoặc `pip`.

**Cách 1: Dùng Pip (Khuyên dùng)**
```bash
# Cài đặt các thư viện cần thiết
pip install fastapi uvicorn[standard] jinja2 python-multipart ujson requests aiofiles
```

**Cách 2: Dùng Conda**
```bash
conda env create -f environment.yml
conda activate vpn_panel
```

---

## 3. Cấu hình Web Panel

1.  Copy file cấu hình mẫu:
    ```bash
    cp config.ini.example config.ini
    ```

2.  Chỉnh sửa `config.ini`:
    ```ini
    [Security]
    # Đổi mật khẩu admin quản trị web
    admin_password = your_secure_password
    # Chuỗi bí mật cho session cookie (đổi chuỗi ngẫu nhiên dài)
    secret_key = change_this_to_a_random_secret_string

    [Paths]
    # Đường dẫn output file .ovpn (thường để trong folder web để tải hoặc gửi đi)
    ovpn_out_dir = ovpn/
    
    # Đường dẫn EasyRSA (Mặc định do script cài đặt tạo ra)
    easy_rsa_dir = /etc/openvpn/server/easy-rsa
    
    # File cấu hình chung cho client (quan trọng)
    client_common = /etc/openvpn/server/client-common.txt
    
    # File theo dõi IP tĩnh của OpenVPN
    ipp_file = /etc/openvpn/server/ipp.txt

    [Network]
    # IP hoặc Domain của VPN Server (dùng cho tính năng khóa User)
    vpn_gateway = 10.8.0.1
    # Port web portal (nếu dùng tính năng captive portal)
    portal_port = 8000
    # Link hỗ trợ (hiển thị khi user gặp lỗi)
    mess_link = https://m.me/your_support
    ```

---

## 4. Chạy Web Panel với Supervisor

Để Web Panel chạy ngầm bền bỉ và tự khởi động lại khi gặp lỗi, chúng ta sử dụng `supervisor`.

### Bước 4.1: Cài đặt Supervisor
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install supervisor -y

# CentOS/RHEL
sudo yum install supervisor -y
```

### Bước 4.2: Tạo file cấu hình
Tạo file `/etc/supervisor/conf.d/vpn_panel.conf` (Ubuntu) hoặc `/etc/supervisord.d/vpn_panel.ini` (CentOS) với nội dung sau:

**Lưu ý:** Thay đổi `/path/to/your/project` thành đường dẫn thực tế chứa code (ví dụ: `/data/openvpn`).

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

*Nếu bạn dùng môi trường ảo (venv/conda), hãy thay `/usr/bin/python3` bằng đường dẫn python trong môi trường ảo đó.*

### Bước 4.3: Khởi động service

```bash
# Cập nhật cấu hình mới
sudo supervisorctl reread
sudo supervisorctl update

# Khởi động Web Panel
sudo supervisorctl start vpn_panel

# Kiểm tra trạng thái
sudo supervisorctl status
```

---

## 5. Sử dụng

1.  Truy cập trình duyệt: `http://<IP_SERVER>:8000`
2.  Đăng nhập bằng mật khẩu đã đặt trong `config.ini`.
3.  **Dashboard**:
    *   **Users**: Thêm user mới, lấy mã OTP tải file, khóa/mở khóa user.
    *   **Settings**: Chỉnh sửa cấu hình Server và Client.
    *   **Logs**: Xem log hệ thống để debug.

### Lưu ý quan trọng
*   Ứng dụng chạy với quyền **ROOT** (user=root trong supervisor) vì cần quyền truy cập `/etc/openvpn`, chạy lệnh `iptables` và `systemctl`. Hãy bảo vệ port 8000 cẩn thận (dùng Firewall hoặc VPN để truy cập).
*   Chức năng **Restart Service** trên Web yêu cầu systemd, hoạt động tốt nhất trên Linux server tiêu chuẩn.

---

## Cấu trúc thư mục

```
/data/openvpn/
├── main.py              # Mã nguồn chính (FastAPI)
├── openvpn-install.sh   # Script cài đặt OpenVPN (Bash)
├── config.ini           # File cấu hình (Tự tạo từ .example)
├── templates/           # Giao diện HTML (Jinja2)
├── static/              # File tĩnh (CSS, JS, Installer MSI)
└── ovpn/                # Thư mục chứa file .ovpn đã tạo
```
