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
        
        # 1. Update Expiry Date
        if self.purchase_date and self.duration_days:
            if self.duration_days >= 36500:
                self.expiry_date = timezone.datetime(2999, 12, 31).date()
            else:
                self.expiry_date = self.purchase_date + timedelta(days=self.duration_days)
        
        # 2. Determine Status (Auto)
        today = timezone.now().date()
        if self.status != 'CANCELED':
            if self.expiry_date and self.expiry_date < today:
                self.status = 'EXPIRED'
            elif self.duration_days == 3:
                self.status = 'DEMO'
            else:
                self.status = 'ACTIVE'

        # 3. Handle Auto Lock/Unlock based on Status
        old_user = CustomUser.objects.filter(pk=self.pk).first()
        is_new = self.pk is None
        
        # Determine if VPN should be enabled
        should_be_enabled = (self.status in ['ACTIVE', 'DEMO'])
        self.is_vpn_enabled = should_be_enabled

        super().save(*args, **kwargs)

        # 4. Sync with OpenVPN System (only if status changed)
        if not is_new and old_user:
            if old_user.is_vpn_enabled != self.is_vpn_enabled:
                mode = "unlock" if self.is_vpn_enabled else "lock"
                if hasattr(self, 'vpn_client'):
                    VPNService.toggle_lock(self.vpn_client.name, self.vpn_client.ip_address or "0.0.0.0", mode)

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
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
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
