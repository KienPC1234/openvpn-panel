from django.core.management.base import BaseCommand
from vpn_panel.models import TrafficSnapshot, Setting
from vpn_panel.services import VPNService
import time
from django.conf import settings
from pathlib import Path

class Command(BaseCommand):
    help = 'Collect network traffic snapshots periodically'

    def handle(self, *args, **options):
        self.stdout.write("Starting stats collection...")
        try:
            while True:
                interfaces = VPNService.get_monitored_interfaces()
                # Simplified: just read /proc/net/dev directly for total interface traffic
                if Path("/proc/net/dev").exists():
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
                
                # Keep only last 100 snapshots per interface to save space
                for iface in interfaces:
                    ids_to_keep = TrafficSnapshot.objects.filter(interface=iface).values_list('id', flat=True)[:100]
                    TrafficSnapshot.objects.filter(interface=iface).exclude(id__in=list(ids_to_keep)).delete()

                time.sleep(60) # Collect every minute
        except KeyboardInterrupt:
            self.stdout.write("Stopping collection.")
