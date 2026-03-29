from celery import shared_task
from .models import TrafficSnapshot
from .services import VPNService
from pathlib import Path
from django.utils.translation import gettext_lazy as _, gettext
from django.core.mail import send_mail
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
            # With 10s intervals, 600 snaps = 100 minutes of history
            retention = int(VPNService.get_vpn_setting('TRAFFIC_SNAPSHOT_RETENTION', '600'))
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
    """Daily sync of statuses: calculates active states and automatically locks users 3 days after expiry."""
    from .models import CustomUser
    from django.utils import timezone
    from datetime import timedelta
    from webpush import send_user_notification

    today = timezone.now().date()
    warning_date = today + timedelta(days=3)
    
    users = CustomUser.objects.exclude(is_superuser=True)
    stats = {"locked": 0, "warned": 0, "synced": 0}

    for user in users:
        # 1. Automatic Lock: 3 days after expiry
        if user.expiry_date and user.expiry_date < (today - timedelta(days=3)):
            if user.is_vpn_enabled:
                user.is_vpn_enabled = False
                user.save(update_fields=['is_vpn_enabled'])
                stats["locked"] += 1
                
                # Push Notification for Expiry
                payload = {
                    "head": "Tài khoản hết hạn 🔴",
                    "body": f"Tài khoản {user.username} đã hết hạn quá 3 ngày và bị khóa. Vui lòng gia hạn ngay!",
                    "icon": "/static/images/logo.png"
                }
                try:
                    logger.info(f"Sending expiry webpush to user {user.username}")
                    send_user_notification(user=user, payload=payload, ttl=3600)
                except Exception as e:
                    logger.error(f"Failed to send expiry webpush to {user.username}: {e}")

        # 2. Expiry Warning: Exactly 3 days before
        elif user.expiry_date == warning_date:
            # Push Notification
            payload = {
                "head": "Sắp hết hạn ⚠️",
                "body": "Gói cước của bạn sẽ hết hạn sau 3 ngày nữa. Hãy nạp thêm để duy trì kết nối!",
                "icon": "/static/images/logo.png"
            }
            try:
                logger.info(f"Sending warning webpush to user {user.username}")
                send_user_notification(user=user, payload=payload, ttl=3600)
            except Exception as e:
                logger.error(f"Failed to send warning webpush to {user.username}: {e}")
            
            # Email Notification
            if user.email:
                subject = "Thông báo: Tài khoản VPN của bạn sắp hết hạn"
                message = f"Xin chào {user.full_name or user.username},\n\nĐây là thông báo nhắc nhở tài khoản VPN của bạn sẽ hết hạn vào ngày {user.expiry_date.strftime('%d/%m/%Y')} (trong 3 ngày tới).\n\nVui lòng gia hạn sớm để tránh bị gián đoạn dịch vụ.\n\nTrân trọng,\nĐội ngũ {VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            stats["warned"] += 1

        # 3. Regular Status Sync
        user.save()
        stats["synced"] += 1
    
    return f"Sync complete: {stats['synced']} synced, {stats['locked']} auto-locked, {stats['warned']} warned."

@shared_task
def apply_vpn_lock_state(client_name, mode, user_pk):
    """Executes the VPN lock/unlock asynchronously and notifies the user."""
    from .models import CustomUser
    status_map = VPNService.get_client_status_map()
    # Try to get IP from status log first (real-time)
    current_ip = status_map.get(client_name)
    
    user = CustomUser.objects.filter(pk=user_pk).first()
    if not user: return "User not found"
    
    # Fallback to DB IP if not connected
    if not current_ip and hasattr(user, 'vpn_client'):
        current_ip = user.vpn_client.ip_address

    if not current_ip or current_ip == "0.0.0.0":
        return f"Cannot {mode} {client_name}: IP not found and user not connected."

    success, msg = VPNService.toggle_lock(client_name, current_ip, mode)
    
    if success:
        # Sync DB state to match firewall
        if hasattr(user, 'vpn_client'):
            user.vpn_client.is_locked = (mode == "lock")
            # If we got a fresh IP from log, update it
            fresh_ip = status_map.get(client_name)
            if fresh_ip:
                user.vpn_client.ip_address = fresh_ip
            user.vpn_client.save(update_fields=['is_locked', 'ip_address'])

        # Send webpush notification 
        from webpush import send_user_notification
        action_vn = "Mở khóa" if mode == "unlock" else "Khóa"
        payload = {
            "head": f"Hệ thống: {action_vn} ✅",
            "body": f"Tài khoản {user.username} đã được {action_vn.lower()} thành công trên tường lửa.",
            "icon": "/static/images/logo.png"
        }
        try:
            logger.info(f"Sending lock/unlock webpush to user {user.username} (mode: {mode})")
            send_user_notification(user=user, payload=payload, ttl=3600)
        except Exception as e:
            logger.error(f"Failed to send lock/unlock webpush to {user.username}: {e}")
                
    return f"Result for {client_name} ({mode}): {msg}"
@shared_task
def send_bulk_announcement(announcement_id):
    from .models import Announcement, CustomUser
    from django.core.mail import send_mail
    from django.utils.html import strip_tags
    
    try:
        ann = Announcement.objects.get(pk=announcement_id)
        users = CustomUser.objects.filter(is_active=True).exclude(email='')
        
        count = 0
        for user in users:
            try:
                send_mail(
                    subject=ann.subject,
                    message=strip_tags(ann.content),
                    from_email=None,
                    recipient_list=[user.email],
                    html_message=ann.content,
                    fail_silently=True
                )
                count += 1
            except:
                pass
        
        ann.recipients_count = count
        ann.save()
        logger.info(f"Broadcasted announcement '{ann.subject}' to {count} users.")
        return f"Sent to {count} users."
    except Exception as e:
        logger.error(f"Failed to broadcast announcement: {e}")
        return str(e)
