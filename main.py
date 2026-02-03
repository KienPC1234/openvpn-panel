import os
import sys
import subprocess
import configparser
import time
import random
import string
import secrets
import logging
import shutil
import datetime
import asyncio
import re
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Optional, List, Dict

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyCookie

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__) 

# --- ROOT CHECK ---
if os.geteuid() != 0:
    logger.critical("Application must be run as ROOT (sudo).")
    sys.exit(1)

# --- LOAD CONFIG ---
CONFIG_FILE = Path('config.ini')
if not CONFIG_FILE.exists():
    logger.critical("config.ini not found!")
    sys.exit(1)

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

try:
    ADMIN_PASSWORD = config['Security']['admin_password']
    SECRET_KEY = config['Security']['secret_key'] 
    OVPN_OUT_DIR = Path(config['Paths']['ovpn_out_dir'])
    EASY_RSA_DIR = Path(config['Paths']['easy_rsa_dir'])
    CLIENT_COMMON = Path(config['Paths']['client_common'])
    IPP_FILE = Path(config['Paths']['ipp_file'])
    VPN_GATEWAY = config['Network']['vpn_gateway']
    PORTAL_PORT = config['Network']['portal_port']
    MESS_LINK = config['Network']['mess_link']
    VPN_INTERFACE = config['Network'].get('vpn_interface', 'tun0')
except KeyError as e:
    logger.critical(f"config.ini missing field: {e}")
    sys.exit(1)

# --- CONSTANTS ---
SERVER_CONF_PATH = Path("/etc/openvpn/server/server.conf")
SERVICE_NAME = "openvpn-server@server"
# Chain for FILTER table (Blocking)
FIREWALL_CHAIN = "VPN_CONTROL"

# --- SETUP APP ---
app = FastAPI(title="VPN Manager Panel", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

Path("static/openvpn_installer").mkdir(parents=True, exist_ok=True)
OVPN_OUT_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory storage
otp_storage: Dict[str, Dict] = {}

# --- JWT HELPERS ---
def create_jwt_token(data: dict, expires_delta: float = 86400) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time() + expires_delta)
    
    def b64url(b_data):
        return base64.urlsafe_b64encode(b_data).decode('utf-8').rstrip('=')

    header_enc = b64url(json.dumps(header).encode('utf-8'))
    payload_enc = b64url(json.dumps(payload).encode('utf-8'))
    
    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        f"{header_enc}.{payload_enc}".encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return f"{header_enc}.{payload_enc}.{b64url(signature)}"

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        header_enc, payload_enc, sig_enc = token.split('.')
        
        def b64url_decode(s):
            padding = '=' * (4 - (len(s) % 4))
            return base64.urlsafe_b64decode(s + padding)

        # Verify Signature
        expected_sig = hmac.new(
            SECRET_KEY.encode('utf-8'),
            f"{header_enc}.{payload_enc}".encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(base64.urlsafe_b64encode(expected_sig).decode('utf-8').rstrip('='), sig_enc):
            return None
            
        payload = json.loads(b64url_decode(payload_enc).decode('utf-8'))
        if payload.get("exp", 0) < time.time():
            return None
            
        return payload
    except Exception:
        return None

# --- FIREWALL INIT ---
def init_firewall():
    """Ensure custom chain exists and is linked"""
    # 1. Create Chain if not exists
    subprocess.run(["iptables", "-N", FIREWALL_CHAIN], stderr=subprocess.DEVNULL)
    
    # 2. Check if Jump rule exists in FORWARD
    check = subprocess.run(["iptables", "-C", "FORWARD", "-j", FIREWALL_CHAIN], stderr=subprocess.DEVNULL)
    if check.returncode != 0:
        # Insert at top
        logger.info(f"Adding Jump rule for {FIREWALL_CHAIN}")
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-j", FIREWALL_CHAIN])

def ensure_status_log_config():
    """Ensure OpenVPN server.conf has status log enabled"""
    if not SERVER_CONF_PATH.exists():
        return
    try:
        content = SERVER_CONF_PATH.read_text()
        if not re.search(r'^\s*status\s+', content, re.MULTILINE):
            logger.info("Adding status log configuration to server.conf")
            with open(SERVER_CONF_PATH, 'a') as f:
                f.write("\nstatus /etc/openvpn/server/openvpn-status.log 10\n")
            run_command(["systemctl", "restart", SERVICE_NAME])
    except Exception as e:
        logger.error(f"Error checking server.conf: {e}")

@app.on_event("startup")
def on_startup():
    init_firewall()
    ensure_status_log_config()

# --- HELPER FUNCTIONS ---

def run_command(cmd_list: List[str], cwd: Optional[Path] = None) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd_list, 
            capture_output=True, 
            text=True, 
            check=False,
            cwd=cwd
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except Exception as e:
        logger.error(f"Command failed: {' '.join(cmd_list)}\nError: {e}")
        return False, str(e)

def format_bytes(size):
    try:
        size = float(size)
    except (ValueError, TypeError):
        return "0.00 B"
        
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def get_group_name() -> str:
    """Detect OS group name (nobody/nogroup) similar to openvpn-install.sh"""
    try:
        if Path("/etc/os-release").exists():
            os_data = Path("/etc/os-release").read_text().lower()
            if "ubuntu" in os_data or "debian" in os_data:
                return "nogroup"
            # CentOS/Fedora/Rocky/Alma usually use 'nobody'
            return "nobody"
        if Path("/etc/debian_version").exists():
            return "nogroup"
    except Exception:
        pass
    return "nobody"

def get_status_log_path() -> Optional[Path]:
    if not SERVER_CONF_PATH.exists():
        return None
    try:
        content = SERVER_CONF_PATH.read_text()
        match = re.search(r'^\s*status\s+([\w\./-]+)', content, re.MULTILINE)
        if match:
            path_str = match.group(1)
            path = Path(path_str)
            if not path.is_absolute():
                path = SERVER_CONF_PATH.parent / path
            return path
    except Exception:
        pass
    return None

def check_is_locked(client_name: str) -> bool:
    ip = get_client_ip(client_name)
    if not ip: return False
    # Check if DROP rule exists for this IP in our chain
    cmd = ["iptables", "-C", FIREWALL_CHAIN, "-s", ip, "-j", "DROP"]
    is_locked, _ = run_command(cmd)
    return is_locked

def get_clients() -> List[Dict]:
    index_path = EASY_RSA_DIR / "pki/index.txt"
    if not index_path.exists():
        return []
    
    clients = []
    try:
        with open(index_path, 'r') as f:
            lines = f.readlines()
            
        for line in lines[1:]:
            parts = line.strip().split('=')
            if len(parts) >= 2:
                status_char = line.split('\t')[0]
                identity_info = parts[1]
                name = identity_info.replace("/CN=", "").split('/')[0]
                
                if status_char == 'V':
                    ovpn_path = OVPN_OUT_DIR / f"{name}.ovpn"
                    clients.append({
                        "name": name, 
                        "has_file": ovpn_path.exists(),
                        "locked": check_is_locked(name)
                    })
    except Exception as e:
        logger.error(f"Error parsing clients: {e}")
    return clients

def client_exists(name: str) -> bool:
    index_path = EASY_RSA_DIR / "pki/index.txt"
    if not index_path.exists():
        return False
    try:
        content = index_path.read_text()
        # Only match lines starting with 'V' (Valid) followed by tab, matching the CN
        return re.search(rf"^V\t.*\/CN={re.escape(name)}(\b|/)", content, re.MULTILINE) is not None
    except:
        return False

def get_client_ip(client_name: str) -> Optional[str]:
    if not IPP_FILE.exists():
        return None
    try:
        with open(IPP_FILE, 'r') as f:
            for line in f:
                if line.startswith(f"{client_name},"):
                    return line.strip().split(',')[1]
    except Exception:
        pass
    return None

def delete_rule_while_exists(rule: List[str]):
    """Loop delete to ensure all duplicates are removed"""
    while True:
        res = subprocess.run(rule, capture_output=True)
        if res.returncode != 0:
            break

def toggle_lock_client(client_name: str, action: str) -> tuple[bool, str]:
    ip = get_client_ip(client_name)
    if not ip:
        return False, "IP not found (User has never connected?)"

    # --- CLEANUP (Unlock) ---
    # 1. Remove Filter Rules (DNS & Portal Allow & Block) from custom chain
    delete_rule_while_exists(["iptables", "-D", FIREWALL_CHAIN, "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    delete_rule_while_exists(["iptables", "-D", FIREWALL_CHAIN, "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    # Also remove allowance for Portal Port
    delete_rule_while_exists(["iptables", "-D", FIREWALL_CHAIN, "-s", ip, "-p", "tcp", "--dport", str(PORTAL_PORT), "-d", VPN_GATEWAY, "-j", "ACCEPT"])
    delete_rule_while_exists(["iptables", "-D", FIREWALL_CHAIN, "-s", ip, "-j", "DROP"])
    
    # 2. Remove NAT Redirect Rules (Captive Portal)
    delete_rule_while_exists(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{VPN_GATEWAY}:{PORTAL_PORT}"])
    delete_rule_while_exists(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{VPN_GATEWAY}:{PORTAL_PORT}"])

    # --- APPLY LOCK ---
    if action == 'lock':
        # 1. Allow DNS
        ok, err = run_command(["iptables", "-I", FIREWALL_CHAIN, "1", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        if not ok: return False, err
        ok, err = run_command(["iptables", "-I", FIREWALL_CHAIN, "1", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
        if not ok: return False, err
        
        # 2. Allow Traffic to Portal (Critical Fix)
        # Must allow access to the portal port on the gateway itself
        ok, err = run_command(["iptables", "-I", FIREWALL_CHAIN, "1", "-s", ip, "-p", "tcp", "--dport", str(PORTAL_PORT), "-d", VPN_GATEWAY, "-j", "ACCEPT"])
        if not ok: return False, err

        # 3. Redirect Web Traffic (HTTP/HTTPS) to Portal
        ok, err = run_command(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{VPN_GATEWAY}:{PORTAL_PORT}"])
        if not ok: return False, err
        ok, err = run_command(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{VPN_GATEWAY}:{PORTAL_PORT}"])
        if not ok: return False, err
        
        # 4. Block Everything Else
        # Insert at position 4 (after the 3 Accept rules we just added at pos 1)
        ok, err = run_command(["iptables", "-I", FIREWALL_CHAIN, "4", "-s", ip, "-j", "DROP"])
        if not ok: return False, err

    # Save
    if subprocess.run(["which", "netfilter-persistent"], capture_output=True).returncode == 0:
        run_command(["netfilter-persistent", "save"])
        
    return True, "Success"

def create_ovpn_file(client_name: str) -> bool:
    inline_path = EASY_RSA_DIR / "pki/inline/private" / f"{client_name}.inline"
    if not inline_path.exists():
        return False
    
    try:
        key_content = inline_path.read_text()
        common_content = CLIENT_COMMON.read_text()
        
        full_content = common_content + "\n" + key_content
        clean_lines = [line for line in full_content.splitlines() if not line.strip().startswith('#')]
        
        out_path = OVPN_OUT_DIR / f"{client_name}.ovpn"
        out_path.write_text('\n'.join(clean_lines))
        return True
    except Exception as e:
        logger.error(f"Error creating ovpn file: {e}")
        return False

# --- SYSTEM & SERVICE FUNCTIONS ---

def get_service_status() -> str:
    success, output = run_command(["systemctl", "is-active", SERVICE_NAME])
    return output.strip() if success else "inactive"

def get_network_interfaces() -> List[Dict]:
    interfaces = []
    target_ifaces = ["eth0", VPN_INTERFACE] 
    
    try:
        success, ip_output = run_command(["ip", "-o", "addr", "show"])
        ip_map = {}
        if success:
            for line in ip_output.splitlines():
                parts = line.split()
                if len(parts) >= 4 and "inet" in parts:
                    try:
                        idx = parts.index("inet")
                        name = parts[1]
                        ip = parts[idx+1]
                        ip_map[name] = ip
                    except:
                        pass

        if Path("/proc/net/dev").exists():
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                parts = line.split()
                if len(parts) > 1:
                    name = parts[0].strip(':')
                    if name not in target_ifaces:
                        continue
                    rx = int(parts[1])
                    tx = int(parts[9])
                    interfaces.append({
                        "name": name,
                        "ip": ip_map.get(name, "No IP"),
                        "rx": format_bytes(rx),
                        "tx": format_bytes(tx),
                        "raw_rx": rx,
                        "raw_tx": tx
                    })
    except Exception as e:
        logger.error(f"Net Stats Error: {e}")
    return interfaces

def get_active_connections() -> List[Dict]:
    connections = []
    status_path = get_status_log_path()
    if not status_path or not status_path.exists():
        return []

    try:
        content = status_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for line in lines:
            parts = line.split(',')
            # Format: CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,...
            if parts[0] == "CLIENT_LIST":
                if len(parts) < 8:
                    continue
                
                name = parts[1]
                if name == "Common Name": continue
                
                real_addr = parts[2].rsplit(':', 1)[0]
                virt_addr = parts[3]
                
                try:
                    rx = int(parts[5])
                    tx = int(parts[6])
                except (ValueError, IndexError):
                    rx, tx = 0, 0
                
                connected_since = parts[7]

                connections.append({
                    "name": name,
                    "real_address": real_addr,
                    "virtual_address": virt_addr,
                    "bytes_received": format_bytes(rx),
                    "bytes_sent": format_bytes(tx),
                    "connected_since": connected_since,
                })

    except Exception as e:
        logger.error(f"Error parsing status log: {e}")

    return connections

# --- AUTH ---
cookie_sec = APIKeyCookie(name="session_token", auto_error=False)

async def get_current_user(token: str = Depends(cookie_sec)):
    if not token:
        return None
    payload = verify_jwt_token(token)
    if payload and payload.get("sub") == "admin":
        return "admin"
    return None

def verify_admin(user: str = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return user

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: str = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard")
    
    installers = []
    inst_path = Path("static/openvpn_installer")
    if inst_path.exists():
        installers = [f.name for f in inst_path.iterdir() if f.is_file()]
        
    return templates.TemplateResponse("login.html", {"request": request, "installers": installers})

@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if secrets.compare_digest(password, ADMIN_PASSWORD):
        token = create_jwt_token({"sub": "admin"})
        
        response = RedirectResponse(url="/dashboard", status_code=303)
        # Auto-detect HTTPS
        is_secure = request.url.scheme == "https"
        response.set_cookie(key="session_token", value=token, httponly=True, max_age=86400, samesite="lax", secure=is_secure)
        return response
    return RedirectResponse(url="/?error=Invalid Password", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/")
    response.delete_cookie("session_token")
    return response

@app.get("/m")
async def mess_redirect():
    return RedirectResponse(url=MESS_LINK)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, msg: Optional[str] = None, section: str = "users", user: str = Depends(verify_admin)):
    clients = get_clients()
    common_content = CLIENT_COMMON.read_text() if CLIENT_COMMON.exists() else ""
    server_content = SERVER_CONF_PATH.read_text() if SERVER_CONF_PATH.exists() else ""
    
    service_status = get_service_status()
    network_stats = get_network_interfaces()
    active_conns = get_active_connections()

    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "clients": clients,
        "common_content": common_content,
        "server_content": server_content,
        "service_status": service_status,
        "network_stats": network_stats,
        "active_conns": active_conns,
        "msg": msg,
        "current_section": section
    })

# --- API STATS ---
@app.get("/api/stats")
async def api_stats(user: str = Depends(verify_admin)):
    return {
        "service_status": get_service_status(),
        "active_conns": get_active_connections(),
        "network_stats": get_network_interfaces()
    }

# --- WEBSOCKETS ---
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    token = websocket.cookies.get("session_token")
    payload = verify_jwt_token(token) if token else None
    
    if not payload or payload.get("sub") != "admin":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept() 
    
    cmd = ["journalctl", "-u", SERVICE_NAME, "-f", "-n", "20", "--no-pager", "--output=cat"]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        while True:
            line = await process.stdout.readline()
            if not line: break
            await websocket.send_text(line.decode().strip())
    except Exception:
        pass
    finally:
        if process: 
            try: process.terminate()
            except: pass

@app.websocket("/ws/stats")
async def websocket_stats(websocket: WebSocket):
    token = websocket.cookies.get("session_token")
    payload = verify_jwt_token(token) if token else None
    
    if not payload or payload.get("sub") != "admin":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    try:
        while True:
            stats = {
                "service_status": get_service_status(),
                "active_conns": get_active_connections(),
                "network_stats": get_network_interfaces()
            }
            await websocket.send_json(stats)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass

# --- OTHER API ROUTES ---

@app.post("/api/service/restart")
def restart_service_api(user: str = Depends(verify_admin)):
    success, msg = run_command(["systemctl", "restart", SERVICE_NAME])
    if not success:
        return RedirectResponse(url=f"/dashboard?msg=Restart Failed: {msg}", status_code=303)
    time.sleep(2)
    return RedirectResponse(url="/dashboard?msg=Service Restarted", status_code=303)

@app.post("/api/config/server")
def save_server_config(content: str = Form(...), user: str = Depends(verify_admin)):
    try:
        if SERVER_CONF_PATH.exists():
            shutil.copy2(SERVER_CONF_PATH, SERVER_CONF_PATH.with_suffix(f".bak.{int(time.time())}"))
        SERVER_CONF_PATH.write_text(content)
        return RedirectResponse(url="/dashboard?section=settings&msg=Server Config Saved", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard?section=settings&msg=Error Saving: {e}", status_code=303)

@app.post("/api/client/add")
def add_client(client_name: str = Form(...), user: str = Depends(verify_admin)):
    if len(client_name) > 32:
        raise HTTPException(400, "Name too long (max 32)")
        
    # Logic from openvpn-install.sh: allow alphanumeric, underscore, dash. Replace others with underscore.
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', client_name)
    
    if not safe_name: 
        raise HTTPException(400, "Invalid Name")
    
    if client_exists(safe_name):
        raise HTTPException(400, "Client already exists!")

    try:
        cmd = ["./easyrsa", "--batch", "build-client-full", safe_name, "nopass"]
        success, err = run_command(cmd, cwd=EASY_RSA_DIR)
        
        if not success: 
            raise HTTPException(500, f"Error creating client: {err}")
        
        if not create_ovpn_file(safe_name):
            raise HTTPException(500, "Failed to create config file.")

    except Exception as e:
        # Cleanup if partial failure
        if client_exists(safe_name):
             run_command(["./easyrsa", "--batch", "revoke", safe_name], cwd=EASY_RSA_DIR)
             run_command(["./easyrsa", "--batch", "gen-crl"], cwd=EASY_RSA_DIR)
        
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(500, detail=str(e))

    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/api/client/delete")
def delete_client(client_name: str = Form(...), user: str = Depends(verify_admin)):
    # 1. Revoke in EasyRSA
    run_command(["./easyrsa", "--batch", "revoke", client_name], cwd=EASY_RSA_DIR)
    run_command(["./easyrsa", "--batch", "gen-crl"], cwd=EASY_RSA_DIR)
    
    # 2. Update CRL (Logic from openvpn-install.sh)
    crl_src = EASY_RSA_DIR / "pki/crl.pem"
    crl_dest = Path("/etc/openvpn/server/crl.pem")
    
    if crl_dest.exists():
        crl_dest.unlink()
        
    if crl_src.exists():
        shutil.copy(crl_src, crl_dest)
        # chown nobody:$group_name
        group_name = get_group_name()
        try:
            shutil.chown(crl_dest, user="nobody", group=group_name)
        except Exception as e:
            logger.warning(f"Could not chown crl.pem: {e}")
        crl_dest.chmod(0o644)
    
    # 3. Remove client keys/reqs/crt (Logic from openvpn-install.sh + Cleanup)
    req_file = EASY_RSA_DIR / "pki/reqs" / f"{client_name}.req"
    key_file = EASY_RSA_DIR / "pki/private" / f"{client_name}.key"
    crt_file = EASY_RSA_DIR / "pki/issued" / f"{client_name}.crt"
    
    if req_file.exists(): req_file.unlink()
    if key_file.exists(): key_file.unlink()
    if crt_file.exists(): crt_file.unlink()

    # 4. Remove OVPN file
    ovpn_path = OVPN_OUT_DIR / f"{client_name}.ovpn"
    if ovpn_path.exists(): ovpn_path.unlink()
    
    toggle_lock_client(client_name, "unlock")
    
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/api/client/lock")
def lock_client(client_name: str = Form(...), action: str = Form(...), user: str = Depends(verify_admin)):
    success, msg = toggle_lock_client(client_name, action)
    if not success: raise HTTPException(400, msg)
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/api/common/edit")
def edit_common(content: str = Form(...), user: str = Depends(verify_admin)):
    CLIENT_COMMON.write_text(content)
    return RedirectResponse(url="/dashboard?section=settings", status_code=303)

@app.get("/api/sync")
def sync_files(user: str = Depends(verify_admin)):
    clients = get_clients()
    restored = 0
    for c in clients:
        if not c['has_file']:
            if create_ovpn_file(c['name']):
                restored += 1
    return RedirectResponse(url=f"/dashboard?msg=Restored {restored} files", status_code=303)

@app.post("/api/generate_code")
async def generate_code(client_name: str = Form(...), user: str = Depends(verify_admin)):
    code = ''.join(random.choices(string.digits, k=6))
    otp_storage[code] = { "client": client_name, "expire": time.time() + 60 }
    return {"code": code, "ttl": 60}

@app.get("/code", response_class=HTMLResponse)
async def code_page(request: Request):
    return templates.TemplateResponse("code_download.html", {"request": request})

@app.post("/code")
async def process_code(code: str = Form(...)):
    data = otp_storage.get(code)
    if not data or data['expire'] < time.time(): raise HTTPException(400, "Invalid or Expired Code")
    client_name = data['client']
    ovpn_path = OVPN_OUT_DIR / f"{client_name}.ovpn"
    if not ovpn_path.exists(): raise HTTPException(404, "Config not found")
    del otp_storage[code]
    return FileResponse(ovpn_path, filename=f"{client_name}.ovpn")