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
    def get_vpn_setting(key: str, default: any = None) -> any:
        try:
            return Setting.objects.get(key=key).value
        except Setting.DoesNotExist:
            return settings.VPN_SETTINGS.get(key, default)

    @classmethod
    def get_monitored_interfaces(cls) -> List[str]:
        val = cls.get_vpn_setting('MONITORED_INTERFACES', 'eth0,tun0')
        if isinstance(val, list): return val
        return [i.strip() for i in val.split(',')]

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
        service_name = cls.get_vpn_setting('SERVICE_NAME', 'openvpn-server@server')
        success, output = cls.run_command(["systemctl", "is-active", service_name])
        return output.strip() if success else "inactive"

    @classmethod
    def format_speed(cls, bytes_per_sec: float) -> str:
        """Formats bandwidth (bytes/sec) into human readable speed (e.g., 1.5 MB/s)."""
        if bytes_per_sec < 0: bytes_per_sec = 0
        power = 1024
        n = 0
        power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
        while bytes_per_sec > power:
            bytes_per_sec /= power
            n += 1
        return f"{bytes_per_sec:.1f} {power_labels[n]}B/s"

    @classmethod
    def get_network_interfaces(cls) -> List[Dict]:
        """Returns summarized stats for all monitored interfaces, including real-time speed."""
        from .models import TrafficSnapshot
        from django.utils import timezone
        
        interfaces = []
        target_ifaces = cls.get_monitored_interfaces()
        
        try:
            # 1. Get current IPs
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
                        except: pass
            
            # 2. Get current counters from system
            if Path("/proc/net/dev").exists():
                with open("/proc/net/dev", "r") as f:
                    lines = f.readlines()
                
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) > 1:
                        name = parts[0].strip(':')
                        if name not in target_ifaces: continue
                        
                        rx_total, tx_total = int(parts[1]), int(parts[9])
                        
                        # Calculate Speed (deltas since last snapshot)
                        last_snap = TrafficSnapshot.objects.filter(interface=name).first()
                        speed_rx_str = "0 B/s"
                        speed_tx_str = "0 B/s"
                        
                        if last_snap:
                            dt = (timezone.now() - last_snap.timestamp).total_seconds()
                            if dt > 0.5: # 0.5s minimum to avoid spikes
                                speed_rx_str = cls.format_speed((rx_total - last_snap.rx_bytes) / dt)
                                speed_tx_str = cls.format_speed((tx_total - last_snap.tx_bytes) / dt)
                        
                        interfaces.append({
                            "name": name,
                            "ip": ip_map.get(name, "No IP"),
                            "rx": cls.format_bytes(rx_total),
                            "tx": cls.format_bytes(tx_total),
                            "speed_rx": speed_rx_str,
                            "speed_tx": speed_tx_str,
                        })
        except Exception as e:
            logger.error(f"Bandwidth Calc Error: {e}")
            
        return interfaces

    @classmethod
    def create_ovpn_file(cls, client_name: str) -> bool:
        easy_rsa_dir = Path(cls.get_vpn_setting('EASY_RSA_DIR', '/etc/openvpn/server/easy-rsa'))
        ovpn_out_dir = Path(cls.get_vpn_setting('OVPN_OUT_DIR', str(settings.BASE_DIR / 'ovpn')))
        # Try different possible paths for inline file depending on EasyRSA version
        inline_path = easy_rsa_dir / "pki/inline/private" / f"{client_name}.inline"
        if not inline_path.exists():
            inline_path = easy_rsa_dir / "pki/inline" / f"{client_name}.inline"
            
        client_common = Path(cls.get_vpn_setting('CLIENT_COMMON', '/etc/openvpn/server/client-common.txt'))
        
        if not inline_path.exists():
            logger.warning(f"Inline file missing for {client_name}")
            return False

        try:
            out_path = ovpn_out_dir / f"{client_name}.ovpn"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Read and combine files in Python to avoid shell/sudo path issues
            common_data = ""
            if client_common.exists():
                with open(client_common, 'r') as f:
                    common_data = f.read()
            
            with open(inline_path, 'r') as f:
                inline_data = f.read()
            
            # Filter comments explicitly
            def filter_comments(s):
                return "\n".join(l for l in s.splitlines() if not l.strip().startswith('#'))
                
            final_content = filter_comments(common_data) + "\n\n" + inline_data
            
            with open(out_path, 'w') as f:
                f.write(final_content)
                
            cls.run_command(["sudo", "chmod", "644", str(out_path)])
            return True
        except Exception as e:
            logger.error(f"Error creating ovpn file: {e}")
            return False

    @classmethod
    def add_client(cls, name: str) -> Tuple[bool, str]:
        easy_rsa_dir = Path(cls.get_vpn_setting('EASY_RSA_DIR', '/etc/openvpn/server/easy-rsa'))
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
        easy_rsa_dir = Path(cls.get_vpn_setting('EASY_RSA_DIR', '/etc/openvpn/server/easy-rsa'))
        ovpn_out_dir = Path(cls.get_vpn_setting('OVPN_OUT_DIR', str(settings.BASE_DIR / 'ovpn')))
        
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
        easy_rsa_dir = Path(cls.get_vpn_setting('EASY_RSA_DIR', '/etc/openvpn/server/easy-rsa'))
        server_crl = Path(cls.get_vpn_setting('SERVER_CRL', '/etc/openvpn/server/crl.pem'))
        
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
        """Sophisticated locking with DNS preservation and strict validation."""
        if not ip or ip == "0.0.0.0":
            return False, "IP not found"
            
        gw = cls.get_vpn_setting('VPN_GATEWAY', '10.8.0.1')
        portal_port = cls.get_vpn_setting('PORTAL_PORT', '4553')
        chain = "FORWARD"
        nat_chain = "PREROUTING"

        # Check if already locked to avoid redundant work/errors
        already_locked, _ = cls.run_command(["sudo", "iptables", "-C", chain, "-s", ip, "-j", "DROP"])

        if action == "lock":
            if already_locked: return True, "Already locked"
            
            steps = [
                # 1. Allow DNS (UDP/TCP)
                ["sudo", "iptables", "-I", chain, "1", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                ["sudo", "iptables", "-I", chain, "1", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                # 2. DNAT HTTP/HTTPS to Portal
                ["sudo", "iptables", "-t", "nat", "-I", nat_chain, "1", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"],
                ["sudo", "iptables", "-t", "nat", "-I", nat_chain, "1", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"],
                # 3. Block everything else
                ["sudo", "iptables", "-I", chain, "3", "-s", ip, "-j", "DROP"]
            ]
            
            for cmd in steps:
                success, err = cls.run_command(cmd)
                if not success:
                    return False, f"Rule failed: {' '.join(cmd[1:4])}... Error: {err.strip()}"
            
            cls.save_iptables()
            return True, "Locked"
        else:
            # Unlock logic - Removal is more lenient but we still check the primary DROP rule
            # Remove DNAT
            cls.run_command(["sudo", "iptables", "-t", "nat", "-D", nat_chain, "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            cls.run_command(["sudo", "iptables", "-t", "nat", "-D", nat_chain, "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{gw}:{portal_port}"])
            # Remove DNS Accepts
            cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
            
            # Remove DROP rule (the most important)
            success, err = cls.run_command(["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"])
            
            cls.save_iptables()
            return True, "Unlocked"

    @classmethod
    def save_iptables(cls):
        """Durable save logic matching the shell script."""
        # 1. Try netfilter-persistent
        success, _ = cls.run_command(["sudo", "netfilter-persistent", "save"])
        if success: return
        
        # 2. Manual save to common paths
        if Path("/etc/iptables/rules.v4").exists():
            cls.run_command(["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
        elif Path("/etc/sysconfig/iptables").exists():
            cls.run_command(["sudo", "sh", "-c", "iptables-save > /etc/sysconfig/iptables"])
        else:
            cls.run_command(["sudo", "sh", "-c", "iptables-save > /etc/iptables.rules"])

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
        conf_path = Path(cls.get_vpn_setting('SERVER_CONF', '/etc/openvpn/server/server.conf'))
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
        data = cls.get_client_status_map()
        return list(data.keys())

    @classmethod
    def get_client_status_map(cls) -> Dict[str, str]:
        """Parses the status log and returns mapping of username -> virtual_ip"""
        cache_key = "vpn_client_status_map"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cached_data
            
        status_log = Path(cls.get_vpn_setting('STATUS_LOG', '/etc/openvpn/openvpn-status.log'))
        success, content = cls.run_command(["sudo", "cat", str(status_log)])
        if not success: return {}
        
        mapping = {}
        # Parse routing table for Virtual IP assignments
        is_routing_table = False
        for line in content.splitlines():
            if line.startswith("ROUTING TABLE"):
                is_routing_table = True
                continue
            if line.startswith("GLOBAL STATS"):
                is_routing_table = False
                continue
                
            if is_routing_table and "," in line:
                parts = line.split(',')
                # Format: Virtual Address, Common Name, Real Address, Last Ref
                if len(parts) >= 2 and parts[0].strip() != "Virtual Address":
                    ip = parts[0].strip().split(',')[0]
                    name = parts[1].strip()
                    if name != "UNDEF":
                        mapping[name] = ip
                        
        # Also check CLIENT_LIST for status-version 2/3 compatibility
        for line in content.splitlines():
            if line.startswith("CLIENT_LIST,"):
                parts = line.split(',')
                # Version 2: CLIENT_LIST,Common Name,Real Address,Virtual Address,...
                if len(parts) >= 4:
                    name = parts[1].strip()
                    ip = parts[3].strip().split(',')[0]
                    if name != "UNDEF":
                        mapping[name] = ip

        cache.set(cache_key, mapping, timeout=10)
        return mapping

    @classmethod
    def get_per_user_usage(cls) -> Dict[str, Dict]:
        """Returns map of username -> {rx, tx} from status log."""
        status_log = Path(cls.get_vpn_setting('STATUS_LOG', '/etc/openvpn/openvpn-status.log'))
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
        """Checks if a user's IP is currently DROPPED in iptables FORWARD chain."""
        from .models import Client
        client = Client.objects.filter(name=username).first()
        if not client or not client.ip_address: return False
        
        # Check if the DROP rule exists for this IP in FORWARD
        success, _ = cls.run_command(["sudo", "iptables", "-C", "FORWARD", "-s", client.ip_address, "-j", "DROP"])
        return success

    @classmethod
    def sync_system_users(cls) -> Tuple[int, int]:
        """Scans EasyRSA index.txt and IPP for DB sync and ensures OVPN files exist."""
        easy_rsa_dir = Path(cls.get_vpn_setting('EASY_RSA_DIR', '/etc/openvpn/server/easy-rsa'))
        index_path = easy_rsa_dir / "pki/index.txt"
        ipp_path = Path(cls.get_vpn_setting('IPP_FILE', '/etc/openvpn/server/ipp.txt'))
        ovpn_out_dir = Path(cls.get_vpn_setting('OVPN_OUT_DIR', str(settings.BASE_DIR / 'ovpn')))
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
            ovpn_file = ovpn_out_dir / f"{username}.ovpn"
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
    def get_traffic_history(cls, limit: int = 20) -> Dict[str, List[Dict]]:
        from .models import TrafficSnapshot
        interfaces = cls.get_monitored_interfaces()
        if not interfaces: return {}
        
        history_by_iface = {}
        for iface in interfaces:
            # We need limit + 1 items to calculate deltas
            db_snapshots = list(TrafficSnapshot.objects.filter(interface=iface).order_by('-timestamp')[:limit+1])
            db_snapshots.reverse() # chronological: oldest to newest
            
            history = []
            for i in range(1, len(db_snapshots)):
                prev = db_snapshots[i-1]
                curr = db_snapshots[i]
                
                time_diff = (curr.timestamp - prev.timestamp).total_seconds()
                if time_diff <= 0: time_diff = 1 # Prevent division by zero
                
                rx_speed = max(0, curr.rx_bytes - prev.rx_bytes) / time_diff
                tx_speed = max(0, curr.tx_bytes - prev.tx_bytes) / time_diff
                
                history.append({
                    "time": curr.timestamp.strftime("%H:%M:%S"),
                    "rx": rx_speed,
                    "tx": tx_speed
                })
            history_by_iface[iface] = history
            
        return history_by_iface

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
    def get_service_logs(cls, service: str = 'openvpn', lines: int = 100) -> str:
        """Fetches latest logs for various services, prioritizing error logs as requested."""
        if service == 'openvpn':
            full_service_name = cls.get_vpn_setting('SERVICE_NAME', 'openvpn-server@server')
            # For OpenVPN, we use journalctl. Adding -p err would be too restrictive, 
            # but we can prioritize seeing the latest events.
            success, output = cls.run_command(["sudo", "journalctl", "-u", full_service_name, "--no-pager", "-n", str(lines)])
        elif service in ['panel', 'worker', 'beat']:
             log_file = f"/var/log/vpn_{service}.err.log"
             # Prioritize .err.log
             success, output = cls.run_command(["sudo", "tail", "-n", str(lines), log_file])
             
             # Fallback to .out.log if .err.log is suspiciously empty
             if not output or len(output.strip()) < 5:
                 success_out, output_out = cls.run_command(["sudo", "tail", "-n", str(lines), f"/var/log/vpn_{service}.out.log"])
                 if success_out: output = output_out
        else:
            return f"Unknown service: {service}"
            
        return output if success else f"Error fetching logs for {service}: {output}"
