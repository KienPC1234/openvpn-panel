from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group, User
from django.utils.translation import gettext_lazy as _
from django.utils.safestring import mark_safe
from django.urls import reverse, path
from django.contrib import messages
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.conf import settings
from django.db.models import Sum
from .models import CustomUser, Client, UsageLog, Setting, TrafficSnapshot, OTPCode, VPNConfig, Subscription
from .services import VPNService
from django.utils import timezone
from datetime import timedelta, date
from unfold.admin import ModelAdmin, TabularInline

# Unregister unwanted models to declutter
admin.site.unregister(Group)
try:
    from django_celery_beat.models import PeriodicTask, CrontabSchedule, IntervalSchedule, SolarSchedule, ClockedSchedule
    admin.site.unregister(PeriodicTask)
    admin.site.unregister(CrontabSchedule)
    admin.site.unregister(IntervalSchedule)
    admin.site.unregister(SolarSchedule)
    admin.site.unregister(ClockedSchedule)
except:
    pass

def dashboard_callback(request, context):
    """Provides statistics for the Unfold dashboard."""
    from .models import Subscription, CustomUser
    from .services import VPNService

    total_revenue = Subscription.objects.aggregate(total=Sum('balance'))['total'] or 0
    total_users = CustomUser.objects.exclude(is_superuser=True).count()
    online_users_count = len(VPNService.get_online_users())
    
    # Simple history for a chart (last 7 snapshots)
    import json
    history = VPNService.get_traffic_history(limit=7)

    context.update({
        "stats": [
            {
                "title": _("Tổng Doanh Thu"),
                "value": f"{int(total_revenue/1000):,}k VNĐ",
                "icon": "payments",
                "color": "success",
            },
            {
                "title": _("Tổng Thành Viên"),
                "value": total_users,
                "icon": "group",
                "color": "info",
            },
            {
                "title": _("Người Dùng Online"),
                "value": online_users_count,
                "icon": "sensors",
                "color": "warning",
            },
        ],
        "traffic_history": json.dumps(history),
    })
    return context

@admin.action(description='Gia hạn 30 ngày')
def extend_30_days(modeladmin, request, queryset):
    for user in queryset:
        if user.expiry_date:
            user.expiry_date += timedelta(days=30)
        else:
            user.expiry_date = timezone.now().date() + timedelta(days=30)
        user.save()
    messages.success(request, f"Đã gia hạn {queryset.count()} người dùng thêm 30 ngày.")

@admin.action(description='Gia hạn VÔ CỰC (999 năm)')
def set_infinite_expiry(modeladmin, request, queryset):
    infinite_date = date(2999, 12, 31)
    queryset.update(expiry_date=infinite_date)
    messages.success(request, f"Đã gán thời gian VÔ CỰC cho {queryset.count()} người dùng.")

@admin.action(description='Đồng bộ từ hệ thống (OpenVPN)')
def sync_users_action(modeladmin, request, queryset):
    created, skipped = VPNService.sync_system_users()
    messages.success(request, f"Đồng bộ hoàn tất: {created} mới, {skipped} đã tồn tại.")

@admin.register(CustomUser)
class CustomUserAdmin(ModelAdmin):
    # Fieldsets for Unfold ModelAdmin
    fieldsets = (
        (None, {'fields': ('username', 'password', 'email', 'full_name', 'status', 'is_vpn_enabled')}),
        (_('Gói cước & Thanh toán'), {
            'fields': ('purchase_date', 'duration_days', 'expiry_date', 'balance'),
            'classes': ('wide',),
        }),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    readonly_fields = ('expiry_date', 'is_vpn_enabled')
    list_display = ('username', 'display_name', 'get_client_ip', 'real_status', 'vpn_actions')
    list_filter = ('status', 'is_staff', 'purchase_date')
    search_fields = ('username', 'full_name', 'email')
    actions = [
        'delete_no_ip_users_action', 
        sync_users_action, 
        'rebuild_ovpn_action', 
        'revoke_cert_action', 
        'lock_vpn_action', 
        'unlock_vpn_action'
    ]
    changelist_actions = ('delete_no_ip_users_action', 'sync_users_action_local')

    @admin.action(description='❌ XÓA User chưa có IP (Hệ thống)')
    def delete_no_ip_users_action(self, request, queryset=None):
        from .models import Client, CustomUser
        
        # 1. Collect users who don't have a linked Client or Client has no IP
        # Safety: exclude superusers AND staff (admins)
        to_delete = CustomUser.objects.filter(
            vpn_client__ip_address__isnull=True
        ).exclude(is_superuser=True).exclude(is_staff=True) | CustomUser.objects.filter(
            vpn_client__isnull=True
        ).exclude(is_superuser=True).exclude(is_staff=True)
        
        count = 0
        for user in to_delete:
            try:
                # Revoke cert if possible
                VPNService.revoke_client(user.username)
                # Ensure mandatory fields for simple-history
                if not user.purchase_date:
                    user.purchase_date = timezone.now().date()
                    user.save(update_fields=['purchase_date'])
                
                # Delete from DB
                user.delete()
                count += 1
            except Exception as e:
                messages.error(request, f"Lỗi xóa user {user.username}: {str(e)}")
        
        messages.warning(request, f"Đã xóa {count} user không có thông tin IP hệ thống.")
        return None # Prevent further processing

    @admin.action(description='Đồng bộ từ VPN')
    def sync_users_action_local(self, request, queryset=None):
        created, skipped = VPNService.sync_system_users()
        messages.success(request, f"Đồng bộ hoàn tất: {created} mới, {skipped} đã tồn tại.")

    def save_model(self, request, obj, form, change):
        is_new = obj.pk is None
        super().save_model(request, obj, form, change)
        if is_new:
            success, result = VPNService.add_client(obj.username)
            if success:
                from .models import Client
                Client.objects.get_or_create(user=obj, name=obj.username, defaults={'has_ovpn_file': True})
                messages.success(request, f"Đã tự động tạo chứng chỉ VPN cho {obj.username}")
            else:
                messages.error(request, f"Lỗi tạo chứng chỉ VPN: {result}")

    @admin.action(description='Tạo lại file .ovpn')
    def rebuild_ovpn_action(self, request, queryset):
        count = 0
        for user in queryset:
            if VPNService.create_ovpn_file(user.username):
                count += 1
        messages.success(request, f"Đã tạo lại {count} file .ovpn.")

    @admin.action(description='THU HỒI chứng chỉ (Revoke)')
    def revoke_cert_action(self, request, queryset):
        for user in queryset:
            success, err = VPNService.revoke_client(user.username)
            if success:
                messages.warning(request, f"Đã thu hồi chứng chỉ của {user.username}")
            else:
                messages.error(request, f"Lỗi thu hồi {user.username}: {err}")

    # ... keeping other display methods ...

    @admin.display(description='Tên hiển thị')
    def display_name(self, obj):
        return obj.full_name or obj.username

    @admin.display(description='IP VPN')
    def get_client_ip(self, obj):
        if hasattr(obj, 'vpn_client'):
            return obj.vpn_client.ip_address or "---"
        return "---"

    @admin.display(description='Trạng thái')
    def real_status(self, obj):
        status = obj.get_realtime_status()
        # Mapping status to Tailwind colors
        colors = {
            "Connected": "bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400",
            "Active": "bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400",
            "Locked (System)": "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400",
            "Locked (DB)": "bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400",
            "Expired": "bg-gray-100 text-gray-700 dark:bg-gray-500/10 dark:text-gray-400"
        }
        cls = colors.get(status, "bg-gray-100 text-gray-700")
        return mark_safe(f'<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium {cls}">{status}</span>')

    @admin.display(description='Hành động')
    def vpn_actions(self, obj):
        otp_url = reverse('admin_generate_user_otp', args=[obj.pk])
        download_url = reverse('download_ovpn', args=[obj.vpn_client.pk]) if hasattr(obj, 'vpn_client') else "#"
        
        # Toggle Lock Button
        lock_url = reverse('admin:vpn_toggle_lock', args=[obj.pk])
        lock_btn_text = "🔒 Khóa" if obj.is_vpn_enabled else "✅ Mở"
        lock_btn_color = "bg-red-600 hover:bg-red-700" if obj.is_vpn_enabled else "bg-green-600 hover:bg-green-700"
        
        return mark_safe(f'''
            <div class="flex gap-2">
                <a class="px-2 py-1 bg-blue-600 text-white rounded text-xs hover:bg-blue-700 no-underline" href="{otp_url}">🔑 OTP</a>
                <a class="px-2 py-1 bg-indigo-600 text-white rounded text-xs hover:bg-indigo-700 no-underline" href="{download_url}">📥 OVPN</a>
                <a class="px-2 py-1 {lock_btn_color} text-white rounded text-xs no-underline" href="{lock_url}">{lock_btn_text}</a>
            </div>
        ''')

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<path:user_id>/toggle-lock/', self.admin_site.admin_view(self.toggle_vpn_lock), name='vpn_toggle_lock'),
        ]
        return custom_urls + urls

    def toggle_vpn_lock(self, request, user_id):
        user = CustomUser.objects.get(pk=user_id)
        current_state = user.is_vpn_enabled
        user.is_vpn_enabled = not current_state
        user.save()
        
        action_name = "khóa" if current_state else "mở khóa"
        mode = "lock" if current_state else "unlock"
        
        if hasattr(user, 'vpn_client'):
            VPNService.toggle_lock(user.vpn_client.name, user.vpn_client.ip_address or "0.0.0.0", mode)
            
        messages.success(request, f"Đã {action_name} tài khoản {user.username}.")
        return redirect(request.META.get('HTTP_REFERER', 'admin:vpn_panel_customuser_changelist'))

from django.db.models import Sum
from django.utils.formats import number_format

@admin.register(Subscription)
class SubscriptionAdmin(ModelAdmin):
    list_display = ('get_display_name', 'purchase_date', 'get_remaining_days', 'get_balance', 'status_badge')
    list_filter = ('is_vpn_enabled',)
    search_fields = ('full_name', 'username')
    readonly_fields = ('expiry_date',)
    
    fieldsets = (
        (None, {
            'fields': ('full_name', 'purchase_date', 'duration_days', 'expiry_date', 'balance', 'is_vpn_enabled'),
            'classes': ('wide',),
            'description': 'Hệ thống tự động tính Ngày hết hạn dựa trên Ngày mua + Số ngày mua.'
        }),
    )
    
    actions = [sync_users_action, 'rebuild_ovpn_action', 'revoke_cert_action', extend_30_days, set_infinite_expiry, 'lock_vpn_action', 'unlock_vpn_action']

    def save_model(self, request, obj, form, change):
        is_new = obj.pk is None
        super().save_model(request, obj, form, change)
        if is_new:
            success, result = VPNService.add_client(obj.username)
            if success:
                from .models import Client
                Client.objects.get_or_create(user=obj, name=obj.username, defaults={'has_ovpn_file': True})
                messages.success(request, f"Đã tự động tạo chứng chỉ VPN cho {obj.username}")
            else:
                messages.error(request, f"Lỗi tạo chứng chỉ VPN: {result}")

    @admin.action(description='Tạo lại file .ovpn')
    def rebuild_ovpn_action(self, request, queryset):
        count = 0
        for user in queryset:
            if VPNService.create_ovpn_file(user.username):
                count += 1
        messages.success(request, f"Đã tạo lại {count} file .ovpn.")

    @admin.action(description='THU HỒI chứng chỉ (Revoke)')
    def revoke_cert_action(self, request, queryset):
        for user in queryset:
            success, err = VPNService.revoke_client(user.username)
            if success:
                messages.warning(request, f"Đã thu hồi chứng chỉ của {user.username}")
            else:
                messages.error(request, f"Lỗi thu hồi {user.username}: {err}")

    def changelist_view(self, request, extra_context=None):
        total_balance = Subscription.objects.all().aggregate(total=Sum('balance'))['total'] or 0
        extra_context = extra_context or {}
        extra_context['total_revenue'] = total_balance
        return super().changelist_view(request, extra_context=extra_context)

    @admin.display(description='Họ và Tên')
    def get_display_name(self, obj):
        return obj.full_name or f"👤 {obj.username}"

    @admin.display(description='Số tiền')
    def get_balance(self, obj):
        try:
            val = int(obj.balance / 1000)
            return f"{val}k VND"
        except:
            return f"{obj.balance} VND"

    @admin.display(description='Ngày còn lại')
    def get_remaining_days(self, obj):
        days = obj.remaining_days
        if days > 10000 or (obj.expiry_date and obj.expiry_date.year > 2099): 
            return mark_safe('<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400">VÔ CỰC</span>')
        cls = "text-red-600 font-bold" if days < 7 else ""
        return mark_safe(f'<span class="{cls}">{days} ngày</span>')

    @admin.display(description='Thanh toán')
    def status_badge(self, obj):
        if obj.remaining_days > 0 and obj.is_vpn_enabled:
            return mark_safe('<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400">ĐÃ THANH TOÁN</span>')
        return mark_safe('<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400">HẾT HẠN/KHÓA</span>')

    @admin.action(description='Khóa VPN')
    def lock_vpn_action(self, request, queryset):
        from webpush import send_user_notification
        for user in queryset:
            user.is_vpn_enabled = False
            user.save()
            if hasattr(user, 'vpn_client'):
                VPNService.toggle_lock(user.vpn_client.name, user.vpn_client.ip_address or "0.0.0.0", "lock")
            
            # Send Push
            payload = {"head": "Tài khoản ĐÃ KHÓA 🔒", "body": "Tài khoản VPN của bạn đã bị khóa bởi quản trị viên.", "icon": "/static/images/logo.png"}
            send_user_notification(user=user, payload=payload, ttl=3600)

        messages.warning(request, f"Đã khóa {queryset.count()} tài khoản.")

    @admin.action(description='Mở khóa VPN')
    def unlock_vpn_action(self, request, queryset):
        from webpush import send_user_notification
        for user in queryset:
            user.is_vpn_enabled = True
            user.save()
            if hasattr(user, 'vpn_client'):
                VPNService.toggle_lock(user.vpn_client.name, user.vpn_client.ip_address or "0.0.0.0", "unlock")
            
            # Send Push
            payload = {"head": "ĐÃ MỞ KHÓA ✅", "body": "Tài khoản VPN của bạn đã được mở khóa. Bạn có thể sử dụng ngay bây giờ.", "icon": "/static/images/logo.png"}
            send_user_notification(user=user, payload=payload, ttl=3600)

        messages.success(request, f"Đã mở khóa {queryset.count()} tài khoản.")

@admin.register(Client)
class ClientAdmin(ModelAdmin):
    list_display = ('name', 'ip_address', 'is_locked', 'has_ovpn_file')
    list_filter = ('is_locked', 'has_ovpn_file')
    search_fields = ('name', 'ip_address')

@admin.register(VPNConfig)
class VPNConfigAdmin(ModelAdmin):
    def has_add_permission(self, request): return False
    def has_delete_permission(self, request, obj=None): return False
    
    def changelist_view(self, request, extra_context=None):
        server_conf_path = settings.VPN_SETTINGS['SERVER_CONF']
        client_common_path = settings.VPN_SETTINGS['CLIENT_COMMON']
        
        if request.method == 'POST':
            config_type = request.POST.get('config_type')
            if config_type == 'server':
                content = request.POST.get('server_conf')
                if VPNService.write_config(server_conf_path, content):
                    VPNService.run_command(["sudo", "systemctl", "restart", settings.VPN_SETTINGS['SERVICE_NAME']])
                    messages.success(request, "Lưu server.conf & Restart OpenVPN thành công!")
                else: messages.error(request, "Lỗi server.conf")
            elif config_type == 'client':
                content = request.POST.get('client_common')
                if VPNService.write_config(client_common_path, content):
                    messages.success(request, "Lưu Template client-common.txt thành công (Không cần restart)")
                else: messages.error(request, "Lỗi client-common.txt")
            return redirect('admin:vpn_panel_vpnconfig_changelist')

        context = {
            **self.admin_site.each_context(request),
            'title': 'Cấu hình Server & Profile Template',
            'server_conf': VPNService.read_config(server_conf_path),
            'client_common': VPNService.read_config(client_common_path),
        }
        return TemplateResponse(request, "admin/vpn_config.html", context)

@admin.register(Setting)
class SettingAdmin(ModelAdmin):
    list_display = ('key', 'value', 'description')

@admin.register(OTPCode)
class OTPCodeAdmin(ModelAdmin):
    list_display = ('user', 'code', 'expires_at', 'is_used')

@admin.register(UsageLog)
class UsageLogAdmin(ModelAdmin):
    list_display = ('user', 'get_rx', 'get_tx', 'timestamp')

    @admin.display(description='Received')
    def get_rx(self, obj):
        return VPNService.format_bytes(obj.bytes_received)

    @admin.display(description='Sent')
    def get_tx(self, obj):
        return VPNService.format_bytes(obj.bytes_sent)

@admin.register(TrafficSnapshot)
class TrafficSnapshotAdmin(ModelAdmin):
    list_display = ('timestamp', 'interface', 'rx_bytes', 'tx_bytes')
