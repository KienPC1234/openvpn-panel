import subprocess
import logging
import re
import shutil
import time
import secrets
import string
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from django.conf import settings
from django.core.cache import cache
from .models import Setting

logger = logging.getLogger(__name__)

class VPNService:
    @staticmethod
    def get_monitored_interfaces() -> List[str]:
        try:
            setting = Setting.objects.get(key='MONITORED_INTERFACES')
            return [i.strip() for i in setting.value.split(',')]
        except Setting.DoesNotExist:
            return settings.VPN_SETTINGS.get('MONITORED_INTERFACES', ['eth0', 'tun0'])

    @staticmethod
    def run_command(cmd_list: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str]:
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

    @staticmethod
    def format_bytes(size: float) -> str:
        try:
            size = float(size)
        except (ValueError, TypeError):
            return "0.00 B"
        power = 2**10
        n = 0
        power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
        while size > power:
            size /= power
            n += 1
        return f"{size:.2f} {power_labels[n]}B"

    @classmethod
    def get_service_status(cls) -> str:
        service_name = settings.VPN_SETTINGS['SERVICE_NAME']
        success, output = cls.run_command(["systemctl", "is-active", service_name])
        return output.strip() if success else "inactive"

    @classmethod
    def get_network_interfaces(cls) -> List[Dict]:
        interfaces = []
        target_ifaces = cls.get_monitored_interfaces()
        try:
            success, ip_output = cls.run_command(["ip", "-o", "addr", "show"])
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
                        if name not in target_ifaces: continue
                        rx, tx = int(parts[1]), int(parts[9])
                        interfaces.append({
                            "name": name,
                            "ip": ip_map.get(name, "No IP"),
                            "rx": cls.format_bytes(rx),
                            "tx": cls.format_bytes(tx),
                        })
        except Exception as e:
            logger.error(f"Net Stats Error: {e}")
        return interfaces

    @classmethod
    def create_ovpn_file(cls, client_name: str) -> bool:
        easy_rsa_dir = settings.VPN_SETTINGS['EASY_RSA_DIR']
        ovpn_out_dir = settings.VPN_SETTINGS['OVPN_OUT_DIR']
        # Try different possible paths for inline file depending on EasyRSA version
        inline_path = easy_rsa_dir / "pki/inline/private" / f"{client_name}.inline"
        if not inline_path.exists():
            inline_path = easy_rsa_dir / "pki/inline" / f"{client_name}.inline"
            
        client_common = settings.VPN_SETTINGS.get('CLIENT_COMMON', Path('/etc/openvpn/server/client-common.txt'))
        
        if not inline_path.exists():
            logger.warning(f"Inline file missing for {client_name}")
            return False

        try:
            out_path = ovpn_out_dir / f"{client_name}.ovpn"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            
            cmd = f"grep -vh '^#' {client_common} {inline_path} > {out_path}"
            success, err = cls.run_command(["sudo", "sh", "-c", cmd])
            
            if success:
                cls.run_command(["sudo", "chmod", "644", str(out_path)])
                return True
            else:
                logger.error(f"Grep failed: {err}")
                return False
        except Exception as e:
            logger.error(f"Error creating ovpn file: {e}")
            return False

    @classmethod
    def add_client(cls, name: str) -> Tuple[bool, str]:
        easy_rsa_dir = settings.VPN_SETTINGS['EASY_RSA_DIR']
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        
        # Check if already exists in easyrsa
        index_path = easy_rsa_dir / "pki/index.txt"
        success_check, output = cls.run_command(["sudo", "grep", f"/CN={safe_name}$", str(index_path)])
        if success_check and output.strip().startswith("V"):
            # Already exists, just ensure OVPN is there
            cls.create_ovpn_file(safe_name)
            return True, safe_name

        success, err = cls.run_command(["sudo", "./easyrsa", "--batch", "build-client-full", safe_name, "nopass"], cwd=easy_rsa_dir)
        if not success: return False, f"EasyRSA failed: {err}"
        if cls.create_ovpn_file(safe_name):
            return True, safe_name
        return False, "Failed to create OVPN file"

    @classmethod
    def revoke_client(cls, name: str) -> Tuple[bool, str]:
        easy_rsa_dir = settings.VPN_SETTINGS['EASY_RSA_DIR']
        ovpn_out_dir = settings.VPN_SETTINGS['OVPN_OUT_DIR']
        
        # 1. EasyRSA Revoke
        success, err = cls.run_command(["sudo", "./easyrsa", "--batch", "revoke", name], cwd=easy_rsa_dir)
        if not success: return False, f"Revocation failed: {err}"
        
        # 2. File Cleanup (as in Nyr script)
        cls.run_command(["sudo", "rm", "-f", str(easy_rsa_dir / f"pki/reqs/{name}.req")])
        cls.run_command(["sudo", "rm", "-f", str(easy_rsa_dir / f"pki/private/{name}.key")])
        cls.run_command(["sudo", "rm", "-f", str(ovpn_out_dir / f"{name}.ovpn")])
        
        # 3. Regenerate CRL
        return cls.regenerate_crl()

    @classmethod
    def regenerate_crl(cls) -> Tuple[bool, str]:
        easy_rsa_dir = settings.VPN_SETTINGS['EASY_RSA_DIR']
        server_crl = Path("/etc/openvpn/server/crl.pem")
        
        success, err = cls.run_command(["sudo", "./easyrsa", "--batch", "gen-crl"], cwd=easy_rsa_dir)
        if not success: return False, f"CRL generation failed: {err}"
        
        # Copy to OpenVPN dir as per Nyr script logic
        pki_crl = easy_rsa_dir / "pki/crl.pem"
        cls.run_command(["sudo", "cp", str(pki_crl), str(server_crl)])
        cls.run_command(["sudo", "chown", "nobody:nogroup", str(server_crl)])
        cls.run_command(["sudo", "chmod", "644", str(server_crl)])
        
        return True, "CRL updated"

    @classmethod
    def toggle_lock(cls, client_name: str, ip: str, action: str) -> Tuple[bool, str]:
        """Sophisticated locking with DNS preservation and HTTP redirection."""
        if not ip or ip == "0.0.0.0":
            return False, "IP not found"
            
        gw = "10.8.0.1"
        portal_port = "8000" # Django port
        chain = "FORWARD"
        nat_chain = "PREROUTING"

        if action == "lock":
            # 1. Allow DNS
            cls.run_command(["sudo", "iptables", "-I", chain, "1", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            cls.run_command(["sudo", "iptables", "-I", chain, "1", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
            # 2. Redirect Web
            cls.run_command(["sudo", "iptables", "-t", "nat", "-I", nat_chain, "1", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            cls.run_command(["sudo", "iptables", "-t", "nat", "-I", nat_chain, "1", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            # 3. Drop all else
            cls.run_command(["sudo", "iptables", "-I", chain, "3", "-s", ip, "-j", "DROP"])
            cls.save_iptables()
            return True, "Locked"
        else:
            # Unlock logic - delete all specific rules for this IP
            # We use semicolon for multiple deletions if possible, or just individual calls
            cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
            cls.run_command(["sudo", "iptables", "-t", "nat", "-D", nat_chain, "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            cls.run_command(["sudo", "iptables", "-t", "nat", "-D", nat_chain, "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"])
            cls.save_iptables()
            return True, "Unlocked"

    @classmethod
    def save_iptables(cls):
        if Path("/etc/iptables/rules.v4").exists():
            cls.run_command(["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
        elif Path("/etc/sysconfig/iptables").exists():
            cls.run_command(["sudo", "sh", "-c", "iptables-save > /etc/sysconfig/iptables"])
        cls.run_command(["sudo", "iptables-save", ">", "/tmp/iptables.rules"]) # Fallback/Backup

    @staticmethod
    def generate_otp(client_name: str, expiry_seconds: int = 120) -> str:
        code = ''.join(secrets.choice(string.digits) for _ in range(4))
        cache.set(f"otp_{code}", client_name, timeout=expiry_seconds)
        return code

    @staticmethod
    def verify_otp(code: str) -> Optional[str]:
        return cache.get(f"otp_{code}")

    @classmethod
    def enable_lan_support(cls) -> bool:
        conf_path = settings.VPN_SETTINGS['SERVER_CONF']
        if not conf_path.exists(): return False
        try:
            content = conf_path.read_text()
            if "client-to-client" not in content:
                with open(conf_path, 'a') as f:
                    f.write("\nclient-to-client\n")
                cls.run_command(["systemctl", "restart", settings.VPN_SETTINGS['SERVICE_NAME']])
            return True
        except Exception as e:
            logger.error(f"Error enabling LAN support: {e}")
            return False
    @classmethod
    def get_online_users(cls) -> List[str]:
        """Returns a list of usernames currently connected from status log."""
        status_log = settings.VPN_SETTINGS.get('STATUS_LOG', Path('/etc/openvpn/server/openvpn-status.log'))
        success, content = cls.run_command(["sudo", "cat", str(status_log)])
        if not success: return []
        
        online = []
        for line in content.splitlines():
            if line.startswith("CLIENT_LIST,"):
                parts = line.split(',')
                if len(parts) > 1:
                    name = parts[1].strip()
                    if name != "UNDEF":
                        online.append(name)
            elif "," in line and not line.startswith("HEADER") and not line.startswith("TITLE") and not line.startswith("ROUTING_TABLE") and not line.startswith("GLOBAL_STATS") and not line.startswith("END") and not line.startswith("TIME"):
                # Standard format usually starts with "Common Name" row
                parts = line.split(',')
                if len(parts) > 1 and parts[0].strip() != "Common Name":
                    online.append(parts[0].strip())
        return list(set(online))

    @classmethod
    def get_per_user_usage(cls) -> Dict[str, Dict]:
        """Returns map of username -> {rx, tx} from status log."""
        status_log = settings.VPN_SETTINGS.get('STATUS_LOG', Path('/etc/openvpn/openvpn-status.log'))
        success, content = cls.run_command(["sudo", "cat", str(status_log)])
        if not success: return {}

        usage = {}
        for line in content.splitlines():
            if line.startswith("CLIENT_LIST,"):
                parts = line.split(',')
                # Format: CLIENT_LIST,Name,RealAddr,VirtAddr,VirtIPv6,Rx,Tx,...
                if len(parts) > 6:
                    name = parts[1].strip()
                    if name != "UNDEF":
                        rx = int(parts[5])
                        tx = int(parts[6])
                        usage[name] = {"rx": rx, "tx": tx, "rx_f": cls.format_bytes(rx), "tx_f": cls.format_bytes(tx)}
        return usage

    @classmethod
    def is_user_locked(cls, username: str) -> bool:
        """Checks if a user's IP is currently DROPPED in iptables."""
        from .models import Client
        client = Client.objects.filter(name=username).first()
        if not client or not client.ip_address: return False
        
        success, output = cls.run_command(["sudo", "iptables", "-L", "VPN_CONTROL", "-n"])
        if success and client.ip_address in output:
            return "DROP" in output and client.ip_address in output
        return False

    @classmethod
    def sync_system_users(cls) -> Tuple[int, int]:
        """Scans EasyRSA index.txt and IPP for DB sync and ensures OVPN files exist."""
        index_path = settings.VPN_SETTINGS['EASY_RSA_DIR'] / "pki/index.txt"
        ipp_path = settings.VPN_SETTINGS.get('IPP_FILE', Path('/etc/openvpn/server/ipp.txt'))
        created_count = 0
        skipped_count = 0
        
        # 1. Parse IPs
        ipp_map = {}
        success_ipp, ipp_content = cls.run_command(["sudo", "cat", str(ipp_path)])
        if success_ipp:
            for line in ipp_content.splitlines():
                if ',' in line:
                    name, ip = line.split(',', 1)
                    ipp_map[name.strip()] = ip.strip()

        # 2. Parse valid certs from index.txt
        success, output = cls.run_command(["sudo", "grep", "^V", str(index_path)])
        if not success: return 0, 0

        cert_names = []
        for line in output.splitlines():
            if "/CN=" in line:
                cert_names.append(line.split("/CN=")[-1].strip())

        from .models import CustomUser, Client
        for username in cert_names:
            if username in ["server", "ca"]: continue
            
            user, created = CustomUser.objects.get_or_create(
                username=username,
                defaults={'is_active': True}
            )
            if created:
                created_count += 1
                user.set_unusable_password()
                user.save()
            
            # Link/Update client with IP
            client, _ = Client.objects.update_or_create(
                name=username, 
                defaults={'user': user, 'ip_address': ipp_map.get(username)}
            )
            
            # 3. Ensure OVPN file exists
            ovpn_file = settings.VPN_SETTINGS['OVPN_OUT_DIR'] / f"{username}.ovpn"
            if not ovpn_file.exists():
                cls.create_ovpn_file(username)
                client.has_ovpn_file = True
                client.save()
            elif not client.has_ovpn_file:
                client.has_ovpn_file = True
                client.save()

            skipped_count += 0 if created else 1
            
        return created_count, skipped_count

    @classmethod
    def get_traffic_history(cls, limit: int = 20) -> List[Dict]:
        from .models import TrafficSnapshot
        # Get snapshots for the primary interface (e.g., eth0)
        main_ifaces = cls.get_monitored_interfaces()
        if not main_ifaces: return []
        main_iface = main_ifaces[0]
        snapshots = TrafficSnapshot.objects.filter(interface=main_iface).order_by('-timestamp')[:limit]
        return [
            {
                "time": s.timestamp.strftime("%H:%M:%S"),
                "rx": s.rx_bytes,
                "tx": s.tx_bytes
            } for s in reversed(snapshots)
        ]

    @classmethod
    def read_config(cls, file_path: Path) -> str:
        """Reads a config file via sudo cat."""
        success, content = cls.run_command(["sudo", "cat", str(file_path)])
        return content if success else ""

    @classmethod
    def write_config(cls, file_path: Path, content: str) -> bool:
        """Writes a config file via sudo tee."""
        import subprocess
        try:
            process = subprocess.Popen(
                ['sudo', 'tee', str(file_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=content)
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Error writing config {file_path}: {e}")
            return False

    @classmethod
    def get_service_logs(cls, lines: int = 100) -> str:
        """Fetches the latest service logs using journalctl."""
        service_name = settings.VPN_SETTINGS.get('SERVICE_NAME', 'openvpn-server@server')
        success, output = cls.run_command(["sudo", "journalctl", "-u", service_name, "--no-pager", "-n", str(lines)])
        return output if success else f"Error fetching logs: {output}"
