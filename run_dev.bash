#!/bin/bash

# Kiểm tra xem script có đang chạy ở thư mục gốc của project không
if [ ! -f "main.py" ]; then
    echo "Lỗi: Không tìm thấy main.py. Vui lòng chạy script này từ thư mục gốc của dự án."
    exit 1
fi

# Lấy đường dẫn python hiện tại
PYTHON_EXE=$(which python3)

echo "--- Đang khởi động VPN Manager Panel (DEV MODE) ---"
echo "Python detected: $PYTHON_EXE"

# Kiểm tra xem uvicorn có trong python này không
"$PYTHON_EXE" -c "import uvicorn" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "LỖI: Không tìm thấy module 'uvicorn' trong $PYTHON_EXE."
    echo "---------------------------------------------------------"
    echo "NGUYÊN NHÂN CÓ THỂ:"
    echo "1. Bạn đang chạy 'sudo ./run_dev.bash' hoặc 'sudo bash ...' -> Lệnh sudo làm mất môi trường Conda/Venv."
    echo "   -> HÃY CHẠY: ./run_dev.bash (Không có sudo ở đầu)"
    echo "2. Bạn chưa cài thư viện: pip install uvicorn[standard] fastapi"
    echo "---------------------------------------------------------"
    exit 1
fi

echo "Yêu cầu quyền ROOT để quản lý OpenVPN và Iptables..."

# Chạy uvicorn với sudo, trỏ thẳng vào file python của environment
# --reload: Tự động restart khi thay đổi code
sudo "$PYTHON_EXE" -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
