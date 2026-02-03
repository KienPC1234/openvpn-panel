#!/bin/bash

# ==============================================================================
# TOOL KHÓA VPN - FIX DNS & AUTO POPUP
# ==============================================================================

# CẤU HÌNH
EASY_RSA_DIR="/etc/openvpn/server/easy-rsa"
IPP_FILE="/etc/openvpn/server/ipp.txt"
VPN_GATEWAY="10.8.0.1" 
PORTAL_PORT="4553"

# Kiểm tra quyền root
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ Vui lòng chạy với sudo."
    exit 1
fi

save_iptables() {
    echo "💾 Đang lưu cấu hình iptables..."
    if hash netfilter-persistent 2>/dev/null; then
        netfilter-persistent save
    elif hash iptables-save 2>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4
        elif [[ -f /etc/sysconfig/iptables ]]; then
            iptables-save > /etc/sysconfig/iptables
        else
            iptables-save > /etc/iptables.rules
        fi
    fi
}

clear
echo "============================================="
echo "   🛡️  QUẢN LÝ KHÓA VPN (FIX DNS ERROR)"
echo "============================================="

if [[ ! -f "$EASY_RSA_DIR/pki/index.txt" ]]; then
    echo "❌ Không tìm thấy dữ liệu Easy-RSA."
    exit 1
fi

number_of_clients=$(tail -n +2 "$EASY_RSA_DIR/pki/index.txt" | grep -c "^V")

if [[ "$number_of_clients" == "0" ]]; then
    echo "⚠️  Chưa có Client nào."
    exit 0
fi

echo "📋 Danh sách Client:"
tail -n +2 "$EASY_RSA_DIR/pki/index.txt" | grep "^V" | cut -d '=' -f 2 | nl -s ') '

echo
read -p "👉 Chọn số thứ tự Client: " client_number

if ! [[ "$client_number" =~ ^[0-9]+$ ]] || [ "$client_number" -le 0 ] || [ "$client_number" -gt "$number_of_clients" ]; then
    echo "❌ Sai số thứ tự."
    exit 1
fi

client_name=$(tail -n +2 "$EASY_RSA_DIR/pki/index.txt" | grep "^V" | cut -d '=' -f 2 | sed -n "${client_number}p")
echo "---------------------------------------------"
echo "🔍 Client: $client_name"

client_ip=$(grep "^$client_name," "$IPP_FILE" | cut -d ',' -f 2)

if [[ -z "$client_ip" ]]; then
    echo "❌ LỖI: User chưa có IP tĩnh (Chưa từng kết nối)."
    exit 1
fi

echo "📍 IP: $client_ip"

# KIỂM TRA TRẠNG THÁI
# Check xem có rule DROP DNS không (dấu hiệu của việc đã khóa)
is_locked=0
if iptables -C FORWARD -s "$client_ip" -j DROP 2>/dev/null; then
    is_locked=1
fi

if [[ "$is_locked" == "1" ]]; then
    echo "🔒 TRẠNG THÁI: ĐANG BỊ KHÓA."
    read -p "🔓 MỞ KHÓA (Unlock)? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        # 1. Xóa rule ALLOW DNS (QUAN TRỌNG)
        iptables -D FORWARD -s "$client_ip" -p udp --dport 53 -j ACCEPT 2>/dev/null
        iptables -D FORWARD -s "$client_ip" -p tcp --dport 53 -j ACCEPT 2>/dev/null
        
        # 2. Xóa rule chặn Internet (DROP ALL)
        iptables -D FORWARD -s "$client_ip" -j DROP 2>/dev/null
        
        # 3. Xóa DNAT
        iptables -t nat -D PREROUTING -s "$client_ip" -p tcp --dport 80 -j DNAT --to-destination "$VPN_GATEWAY":"$PORTAL_PORT" 2>/dev/null
        iptables -t nat -D PREROUTING -s "$client_ip" -p tcp --dport 443 -j DNAT --to-destination "$VPN_GATEWAY":"$PORTAL_PORT" 2>/dev/null
        
        save_iptables
        echo "✅ Đã MỞ KHÓA!"
    fi
else
    echo "✅ TRẠNG THÁI: BÌNH THƯỜNG."
    read -p "🔒 KHÓA (Lock) & Hiện thông báo? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        echo "🔄 Đang thiết lập luật chặn..."

        # BƯỚC 1: CHO PHÉP DNS (Để sửa lỗi Resolve DNS)
        # Phải chèn lên đầu (-I 1) để nó được ưu tiên trước lệnh DROP
        iptables -I FORWARD 1 -s "$client_ip" -p udp --dport 53 -j ACCEPT
        iptables -I FORWARD 1 -s "$client_ip" -p tcp --dport 53 -j ACCEPT

        # BƯỚC 2: BẺ LÁI TRAFFIC WEB (Để hiện thông báo)
        iptables -t nat -I PREROUTING 1 -s "$client_ip" -p tcp --dport 80 -j DNAT --to-destination "$VPN_GATEWAY":"$PORTAL_PORT"
        iptables -t nat -I PREROUTING 1 -s "$client_ip" -p tcp --dport 443 -j DNAT --to-destination "$VPN_GATEWAY":"$PORTAL_PORT"
        
        # BƯỚC 3: CHẶN TẤT CẢ CÒN LẠI (Game, SSH,...)
        # Lưu ý: Rule này nằm dưới rule DNS nhờ thứ tự insert, nhưng chặn hết các traffic khác
        # Chúng ta dùng -A (Append) sau rule DNS hoặc insert vào vị trí số 3. 
        # Để an toàn nhất, ta chèn DROP vào vị trí số 3 của FORWARD (sau 2 dòng DNS ở trên)
        iptables -I FORWARD 3 -s "$client_ip" -j DROP
        
        save_iptables
        echo "⛔ Đã KHÓA thành công!"
    fi
fi