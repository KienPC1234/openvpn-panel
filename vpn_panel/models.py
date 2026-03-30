from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from simple_history.models import HistoricalRecords
from datetime import timedelta
from django.utils import timezone

class CustomUser(AbstractUser):
    full_name = models.CharField(_("Full Name"), max_length=150, blank=True)
    purchase_date = models.DateField(_("Purchase Date"), default=timezone.now, null=True, blank=True)
    duration_days = models.IntegerField(_("Duration (Days)"), default=30, null=True, blank=True)
    expiry_date = models.DateField(_("Expiry Date"), null=True, blank=True)
    balance = models.DecimalField(_("Amount Paid"), max_digits=12, decimal_places=2, default=0)
    
    # Status choices
    STATUS_CHOICES = [
        ('ACTIVE', _('Đang hoạt động')),
        ('EXPIRED', _('Hết hạn')),
        ('CANCELED', _('Đã hủy')),
        ('DEMO', _('Dùng thử (3 ngày)')),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    # VPN specific
    is_vpn_enabled = models.BooleanField(default=True)
    requires_profile_update = models.BooleanField(default=False)
    last_usage_update = models.DateTimeField(null=True, blank=True)
    
    history = HistoricalRecords()

    def save(self, *args, **kwargs):
        from .services import VPNService
        
        old_user = CustomUser.objects.filter(pk=self.pk).first()
        is_new = self.pk is None
        today = timezone.now().date()
        grace_days = int(VPNService.get_vpn_setting('GRACE_PERIOD_DAYS', '3'))
        
        # 1. Update Expiry Date if purchase_date/duration_days changed
        subscription_updated = False
        if self.purchase_date and self.duration_days is not None:
            if is_new or (old_user and (old_user.purchase_date != self.purchase_date or old_user.duration_days != self.duration_days)):
                subscription_updated = True
                if self.duration_days >= 36500:
                    self.expiry_date = timezone.datetime(2999, 12, 31).date()
                else:
                    self.expiry_date = self.purchase_date + timedelta(days=self.duration_days)
        
        # 2. Determine Status and Automatic Locking (Grace Period Aware)
        # We only auto-unlock if the subscription was just updated or it's a new user
        # We only auto-lock if its truly expired beyond grace period
        
        if self.status != 'CANCELED':
            if self.expiry_date:
                if self.expiry_date < (today - timedelta(days=grace_days)):
                    self.status = 'EXPIRED'
                    self.is_vpn_enabled = False # Force lock after grace period
                elif self.expiry_date < today:
                    self.status = 'EXPIRED'
                    # We DON'T force lock yet, allowing grace period
                elif self.duration_days == 3:
                    self.status = 'DEMO'
                else:
                    self.status = 'ACTIVE'

            # Auto-unlock logic
            if is_new or subscription_updated:
                # If admin is renewing, we should auto-unlock the user
                if self.expiry_date and self.expiry_date >= today:
                    self.is_vpn_enabled = True
            
        # 3. Detect Manual Unlock for Expired Users via Admin
        # If admin toggles is_vpn_enabled to True on an expired user, we give them extension
        if old_user and not old_user.is_vpn_enabled and self.is_vpn_enabled:
             if self.expiry_date and self.expiry_date < today:
                ext_days = int(VPNService.get_vpn_setting('UNLOCK_FREE_DAYS', '3'))
                # Shift duration forward
                if not self.purchase_date: self.purchase_date = today
                delta = today - self.purchase_date
                self.duration_days = delta.days + ext_days
                self.expiry_date = self.purchase_date + timedelta(days=self.duration_days)
                self.status = 'ACTIVE'
        
        super().save(*args, **kwargs)

        # 4. Sync with OpenVPN System (only if status changed)
        if not is_new and old_user:
            if old_user.is_vpn_enabled != self.is_vpn_enabled:
                mode = "unlock" if self.is_vpn_enabled else "lock"
                # Sync to Client model as well
                if hasattr(self, 'vpn_client'):
                    self.vpn_client.is_locked = not self.is_vpn_enabled
                    self.vpn_client.save(update_fields=['is_locked'])
                    
                    from django.db import transaction
                    from .tasks import apply_vpn_lock_state
                    # Execute the task asynchronously ONLY AFTER the current DB transaction commits
                    transaction.on_commit(lambda: apply_vpn_lock_state.delay(self.vpn_client.name, mode, self.pk))

    @property
    def remaining_days(self):
        if not self.expiry_date or self.is_superuser or self.expiry_date.year > 2099:
            return 999999 # Treat as infinite
        delta = self.expiry_date - timezone.now().date()
        return max(0, delta.days)

    @property
    def status_text(self):
        if self.remaining_days <= 0:
            return "Expired"
        if not self.is_vpn_enabled:
            return "Locked"
        return "Active"

    def get_realtime_status(self):
        """Used in Admin to show more accurate state."""
        from .services import VPNService
        if self.remaining_days <= 0: return "Expired"
        # Check if connected
        online_users = VPNService.get_online_users()
        if self.username in online_users:
            return "Connected"
        # Check if locked in system
        if VPNService.is_user_locked(self.username):
            return "Locked (System)"
        if not self.is_vpn_enabled:
            return "Locked (DB)"
        return "Active"

class OTPCode(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='otps', null=True, blank=True)
    code = models.CharField(max_length=10, unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        from .services import VPNService
        if not self.expires_at:
            hours = int(VPNService.get_vpn_setting('OTP_EXPIRY_HOURS', '24'))
            self.expires_at = timezone.now() + timedelta(hours=hours)
        super().save(*args, **kwargs)

    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()

    def __str__(self):
        return self.code

class Client(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='vpn_client', null=True, blank=True)
    name = models.CharField(_("Client Name"), max_length=100, unique=True)
    ip_address = models.GenericIPAddressField(_("IP Address"), null=True, blank=True)
    is_locked = models.BooleanField(_("Is Locked"), default=False)
    has_ovpn_file = models.BooleanField(_("Has OVPN File"), default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    history = HistoricalRecords()

    def __str__(self):
        return self.name

class UsageLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='usage_logs')
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

class TrafficSnapshot(models.Model):
    interface = models.CharField(max_length=50)
    rx_bytes = models.BigIntegerField()
    tx_bytes = models.BigIntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

class Setting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.key

class VPNConfig(Setting):
    class Meta:
        proxy = True
        verbose_name = "Cấu hình VPN"
        verbose_name_plural = "Cấu hình VPN"

class Subscription(CustomUser):
    class Meta:
        proxy = True
        verbose_name = "Sổ quản lý Gói cước"
        verbose_name_plural = "Sổ quản lý Gói cước"

class Announcement(models.Model):
    subject = models.CharField(_("Subject"), max_length=255)
    content = models.TextField(_("Content (HTML supported)"))
    sent_at = models.DateTimeField(auto_now_add=True)
    recipients_count = models.IntegerField(default=0)
    
    def __str__(self):
        return self.subject
        
class TaskLog(models.Model):
    task_name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=[('SUCCESS', 'Thành công'), ('FAILURE', 'Thất bại'), ('RUNNING', 'Đang chạy')], default='RUNNING')
    result = models.TextField(blank=True)
    error = models.TextField(blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-started_at']
        verbose_name = "Lịch sử Tác vụ"
        verbose_name_plural = "Lịch sử Tác vụ (Debug)"

    def duration(self):
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return "---"

class TaskControl(TaskLog):
    class Meta:
        proxy = True
        verbose_name = "Điều khiển Tác vụ"
        verbose_name_plural = "Điều khiển Tác vụ (Debug)"

class SystemLog(TaskLog):
    class Meta:
        proxy = True
        verbose_name = "Nhật ký Hệ thống"
        verbose_name_plural = "Nhật ký Hệ thống (Logs)"
