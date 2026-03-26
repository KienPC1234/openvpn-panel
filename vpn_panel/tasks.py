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
            
            # Retention: keep last 100 snapshots per interface
            for iface in interfaces:
                ids_to_keep = TrafficSnapshot.objects.filter(interface=iface).order_by('-timestamp').values_list('id', flat=True)[:100]
                TrafficSnapshot.objects.filter(interface=iface).exclude(id__in=list(ids_to_keep)).delete()
                
            return f"Collected stats for {len(interfaces)} interfaces"
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
