from celery import shared_task
from .models import TrafficSnapshot
from .services import VPNService
from pathlib import Path
from django.utils.translation import gettext_lazy as _, gettext
from django.core.mail import send_mail
from django.conf import settings
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
            
            # Retention: keep last N snapshots per interface (Default: 200)
            retention = int(VPNService.get_vpn_setting('TRAFFIC_SNAPSHOT_RETENTION', '200'))
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
        # Determine the date relative to expiry
        if not user.expiry_date:
            continue
            
        # 1. CRITICAL: 3 Days After Expiry -> UNLOCK grace period is over, LOCK NOW
        if user.expiry_date == (today - timedelta(days=3)):
            if user.is_vpn_enabled:
                user.is_vpn_enabled = False
                user.save(update_fields=['is_vpn_enabled'])
                stats["locked"] += 1
                
                # Push Notification
                payload = {
                    "head": "Tài khoản bị khóa 🔴",
                    "body": f"Tài khoản {user.username} đã hết hạn quá 3 ngày và đã bị khóa tự động.",
                    "icon": "/static/images/logo.png"
                }
                try:
                    send_user_notification(user=user, payload=payload, ttl=3600)
                except Exception as e:
                    logger.error(f"Failed to send locked webpush to {user.username}: {e}")
                
                # Email Notification
                if user.email:
                    subject = "Thông báo: Tài khoản VPN của bạn đã bị KHÓA"
                    message = f"Xin chào {user.full_name or user.username},\n\nTài khoản VPN của bạn đã hết hạn vào ngày {user.expiry_date.strftime('%d/%m/%Y')} (đã quá hạn 3 ngày).\n\nHệ thống đã thực hiện khóa dịch vụ tự động. Vui lòng thực hiện gia hạn để tiếp tục sử dụng.\n\nTrân trọng,\nĐội ngũ {VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')}"
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        # 2. GRACE PERIOD: 1 Day After Expiry -> Reminder that they have 2 days left
        elif user.expiry_date == (today - timedelta(days=1)):
             if user.email:
                subject = "Lưu ý: Tài khoản VPN của bạn đã hết hạn"
                message = f"Xin chào {user.full_name or user.username},\n\nTài khoản VPN của bạn đã hết hạn từ hôm qua ({user.expiry_date.strftime('%d/%m/%Y')}).\n\nBạn đang nằm trong thời gian gia hạn 3 ngày. Sau 2 ngày nữa, nếu không gia hạn, hệ thống sẽ tự động khóa tài khoản.\n\nHãy gia hạn sớm nhé!\n\nTrân trọng,\n{VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        # 3. EXPIRY DAY: Notification ON the day it expires
        elif user.expiry_date == today:
             if user.email:
                subject = "Thông báo: Tài khoản VPN của bạn hết hạn hôm nay"
                message = f"Xin chào {user.full_name or user.username},\n\nDịch vụ VPN của bạn sẽ hết hạn vào cuối ngày hôm nay ({user.expiry_date.strftime('%d/%m/%Y')}).\n\nBạn sẽ có thêm 3 ngày gia hạn trước khi hệ thống thực hiện khóa tài khoản.\n\nChúc bạn một ngày tốt lành!\n\n{VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        # 4. PRE-EXPIRY WARNING: 3 Days Before
        elif user.expiry_date == warning_date:
            # Push Notification
            payload = {
                "head": "Sắp hết hạn ⚠️",
                "body": "Gói cước của bạn sẽ hết hạn sau 3 ngày nữa. Hãy nạp thêm để duy trì kết nối!",
                "icon": "/static/images/logo.png"
            }
            try:
                send_user_notification(user=user, payload=payload, ttl=3600)
            except Exception as e:
                logger.error(f"Failed to send warning webpush to {user.username}: {e}")
            
            # Email Notification
            if user.email:
                subject = "Thông báo: Tài khoản VPN của bạn sắp hết hạn"
                message = f"Xin chào {user.full_name or user.username},\n\nĐây là thông báo nhắc nhở tài khoản VPN của bạn sẽ hết hạn vào ngày {user.expiry_date.strftime('%d/%m/%Y')} (trong 3 ngày tới).\n\nVui lòng gia hạn sớm để tránh bị gián đoạn dịch vụ.\n\nTrân trọng,\n{VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            stats["warned"] += 1

        # 5. Regular Status Sync (ensures status field matches expiry logic)
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
@shared_task
def send_welcome_email_task(user_pk, password, site_url, is_admin, email=None):
    from .models import CustomUser
    from django.template.loader import render_to_string
    from django.utils.html import strip_tags
    from django.core.mail import send_mail
    
    user = CustomUser.objects.filter(pk=user_pk).first()
    target_email = email or (user.email if user and user.email else None)
    
    if not (user or email) or not target_email:
        return f"User or email not found (PK: {user_pk}, Email Param: {email})"
        
    try:
        site_name = VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
        footer_text = VPNService.get_vpn_setting('FOOTER_TEXT', 'VPN Management System')
        
        html_content = render_to_string('emails/welcome_email.html', {
            'username': user.username,
            'password': password,
            'full_name': user.full_name or user.username,
            'site_url': site_url,
            'is_admin': is_admin,
            'site_name': site_name,
            'footer_text': footer_text
        })
        
        send_mail(
            subject=f'Chào mừng tới {site_name}!',
            message=strip_tags(html_content),
            from_email=None, 
            recipient_list=[target_email],
            html_message=html_content,
            fail_silently=False
        )
        return f"Welcome email sent to {target_email}"
    except Exception as e:
        logger.error(f"Failed to send welcome email to {target_email}: {e}")
        return str(e)

@shared_task
def send_upcoming_expiry_warnings():
    """Wrapper that triggers sync_user_statuses specifically for warnings/locking checks."""
    return sync_user_statuses()

@shared_task
def cleanup_system_data():
    """Manual trigger to cleanup old logs and snapshots."""
    from .models import TaskLog, TrafficSnapshot
    from django.utils import timezone
    from datetime import timedelta
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    # 1. Clean old TaskLogs
    task_count, _ = TaskLog.objects.filter(started_at__lt=thirty_days_ago).delete()
    
    # 2. Clean old TrafficSnapshots (besides the retention per interface)
    snap_count, _ = TrafficSnapshot.objects.filter(timestamp__lt=thirty_days_ago).delete()
    
    return f"Cleanup complete: {task_count} task logs and {snap_count} old snapshots removed."

@shared_task
def run_system_task_exec(task_type):
    from .models import TaskLog
    from django.utils import timezone
    from .services import VPNService
    
    # Pre-fetch task functions
    from .tasks import sync_user_statuses, collect_traffic_stats, send_upcoming_expiry_warnings, cleanup_system_data
    
    log = TaskLog.objects.create(task_name=f"Run: {task_type}")
    try:
        if task_type == 'sync_user_statuses':
            log.result = sync_user_statuses()
        elif task_type == 'collect_traffic_stats':
            log.result = collect_traffic_stats()
        elif task_type == 'send_expiry_warnings':
            log.result = send_upcoming_expiry_warnings()
        elif task_type == 'cleanup_data':
            log.result = cleanup_system_data()
        elif task_type == 'sync_system_users':
            created, skipped = VPNService.sync_system_users()
            log.result = f"Sync VPN: {created} created, {skipped} skipped."
        elif task_type == 'rebuild_all_ovpn':
            from .models import CustomUser
            users = CustomUser.objects.filter(vpn_client__isnull=False)
            count = 0
            for user in users:
                if VPNService.create_ovpn_file(user.username):
                    count += 1
            log.result = f"Rebuild all: {count}/{users.count()} rebuilt."
        else:
            log.result = "Unknown task type."
            
        log.status = 'SUCCESS'
    except Exception as e:
        log.status = 'FAILURE'
        log.error = str(e)
    finally:
        log.finished_at = timezone.now()
        log.save()
        
    return log.result or log.error
