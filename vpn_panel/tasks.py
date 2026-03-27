from celery import shared_task
from .models import TrafficSnapshot
from .services import VPNService
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@shared_task
def collect_traffic_stats():
    """Periodic task to collect interface traffic and save snapshots."""
    interfaces = VPNService.get_monitored_interfaces()
    if Path("/proc/net/dev").exists():
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                parts = line.split()
                if len(parts) > 1:
                    name = parts[0].strip(':')
                    if name in interfaces:
                        TrafficSnapshot.objects.create(
                            interface=name,
                            rx_bytes=int(parts[1]),
                            tx_bytes=int(parts[9])
                        )
            
            # Retention: keep last N snapshots per interface
            retention = int(VPNService.get_vpn_setting('TRAFFIC_SNAPSHOT_RETENTION', '100'))
            for iface in interfaces:
                ids_to_keep = TrafficSnapshot.objects.filter(interface=iface).order_by('-timestamp').values_list('id', flat=True)[:retention]
                TrafficSnapshot.objects.filter(interface=iface).exclude(id__in=list(ids_to_keep)).delete()
                
            # 1. Sync Client IPs from status log
            status_map = VPNService.get_client_status_map()
            from .models import Client
            for name, ip in status_map.items():
                # Update DB if IP changes or was unknown
                client = Client.objects.filter(name=name).first()
                if client and client.ip_address != ip:
                    client.ip_address = ip
                    client.save()
                    # If user should be locked, force re-apply lock for the NEW IP
                    if client.is_locked:
                        VPNService.toggle_lock(name, ip, "lock")
                        
            return f"Collected stats for {len(interfaces)} interfaces and synced {len(status_map)} clients"
        except Exception as e:
            logger.error(f"Error in collect_traffic_stats task: {e}")
            return str(e)
    return "Proc f-system not found"

@shared_task
def sync_user_statuses():
    """Sync all user statuses and VPN locks by re-saving each user."""
    from .models import CustomUser
    
    users = CustomUser.objects.exclude(is_superuser=True)
    count = 0
    for user in users:
        # Saving will trigger the status-calculation logic in CustomUser.save()
        user.save()
        count += 1
    
    return f"Synced status for {count} users."
