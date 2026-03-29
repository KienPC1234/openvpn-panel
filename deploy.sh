#!/bin/bash
# =====================================================================
# deploy.sh - Build & Restart VPN Panel
# Usage: ./deploy.sh
# =====================================================================

set -e

PYTHON="/home/kien/miniconda3/bin/python"
DIR="/data/openvpn"

cd "$DIR"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()   { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()    { echo -e "${GREEN}✅ $1${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail()  { echo -e "${RED}❌ $1${NC}"; exit 1; }

echo ""
echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}   🚀 VPN Panel Deploy Script${NC}"
echo -e "${CYAN}=====================================================${NC}"
echo ""

# --------------------------------------------------------------------
# 1. BUILD TAILWIND CSS
# --------------------------------------------------------------------
log "Đang build Tailwind CSS..."
# Đảm bảo quyền ghi cho thư mục dist
chown -R "$(stat -c '%U' "$DIR")" "$DIR/theme/static/css/dist" 2>/dev/null || true
if $PYTHON manage.py tailwind build 2>&1; then
    ok "Tailwind CSS build thành công"
else
    fail "Tailwind CSS build thất bại"
fi

# --------------------------------------------------------------------
# 2. COLLECT STATIC FILES
# --------------------------------------------------------------------
log "Đang gom file static (collectstatic)..."
if $PYTHON manage.py collectstatic --noinput 2>&1; then
    ok "Collectstatic hoàn tất"
else
    fail "Collectstatic thất bại"
fi

# --------------------------------------------------------------------
# 3. RESTART SUPERVISOR GROUP
# --------------------------------------------------------------------
log "Đang restart cụm tiến trình vpn..."
SUDO_CMD=""
[ "$(id -u)" -ne 0 ] && SUDO_CMD="sudo"

if $SUDO_CMD supervisorctl restart vpn:* 2>&1; then
    ok "Restart cụm vpn thành công"
else
    fail "Restart supervisor thất bại (kiểm tra quyền)"
fi

# --------------------------------------------------------------------
# 4. KIỂM TRA TRẠNG THÁI
# --------------------------------------------------------------------
echo ""
log "Trạng thái dịch vụ sau deploy:"
$SUDO_CMD supervisorctl status vpn:*

echo ""
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}   ✅ Deploy hoàn tất!${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo ""
