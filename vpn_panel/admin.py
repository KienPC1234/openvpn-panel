from django.contrib import admin
from django.db import models, transaction
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
from .models import CustomUser, Client, UsageLog, Setting, TrafficSnapshot, OTPCode, VPNConfig, Subscription, Announcement, TaskLog, TaskControl, SystemLog, InstallerFile, InstallerManager
from .services import VPNService
from django.utils import timezone
from .tasks import send_bulk_announcement, send_welcome_email_task
from datetime import timedelta, date
from unfold.admin import ModelAdmin, TabularInline
from unfold.decorators import action as unfold_action
from django.utils.translation import activate, get_language
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import secrets, string

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
    """Provides statistics for the Unfold dashboard with error handling."""
    from .models import Subscription, CustomUser
    from .services import VPNService
    import json

    try:
        total_revenue = Subscription.objects.aggregate(total=Sum('balance'))['total'] or 0
        total_users = CustomUser.objects.exclude(is_superuser=True).count()
        
        # Get online users with short timeout/cache check
        online_users_count = 0
        try:
            online_users_count = len(VPNService.get_online_users())
        except:
            pass
            
        # Simple history for a chart (last 7 snapshots)
        history = []
        try:
            history = VPNService.get_traffic_history(limit=7)
        except:
            pass

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
            "last_sync": timezone.now().strftime("%H:%M:%S")
        })
    except Exception as e:
        context.update({
            "stats": [],
            "traffic_history": "[]",
            "dashboard_error": str(e)
        })
    return context

@admin.action(description='Gia hạn 30 ngày')
def extend_30_days(modeladmin, request, queryset):
    days = int(VPNService.get_vpn_setting('EXTENSION_DAYS_DEFAULT', '30'))
    for user in queryset:
        if user.expiry_date:
            user.expiry_date += timedelta(days=days)
        else:
            user.expiry_date = timezone.now().date() + timedelta(days=days)
        user.save()
    messages.success(request, f"Đã gia hạn {queryset.count()} người dùng thêm {days} ngày.")
    return None # Django's admin handles redirect for standard actions

@admin.action(description='Gia hạn VÔ CỰC (999 năm)')
def set_infinite_expiry(modeladmin, request, queryset):
    inf_str = VPNService.get_vpn_setting('INFINITE_DATE', '2999-12-31')
    infinite_date = timezone.datetime.strptime(inf_str, '%Y-%m-%d').date()
    queryset.update(expiry_date=infinite_date)
    messages.success(request, f"Đã gán thời gian VÔ CỰC cho {queryset.count()} người dùng.")
    return None

@admin.action(description='Đồng bộ từ hệ thống (OpenVPN)')
def sync_users_action(modeladmin, request, queryset):
    created, skipped = VPNService.sync_system_users()
    messages.success(request, f"Đồng bộ hoàn tất: {created} mới, {skipped} đã tồn tại.")

from django import forms

class CustomUserForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'email' in self.fields:
            self.fields['email'].required = True
            self.fields['email'].label = "Email (Bắt buộc để gửi tài khoản)"
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'full_name', 'status', 'is_vpn_enabled', 'purchase_date', 'duration_days', 'balance', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')

@admin.register(CustomUser)
class CustomUserAdmin(ModelAdmin):
    form = CustomUserForm
    fieldsets = (
        (None, {'fields': ('username', 'email', 'full_name', 'status', 'is_vpn_enabled', 'password_reset_link')}),
        (_('Gói cước & Thanh toán'), {
            'fields': ('purchase_date', 'duration_days', 'expiry_date', 'balance'),
            'classes': ('wide',),
        }),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    readonly_fields = ('expiry_date', 'is_vpn_enabled', 'password_reset_link')
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
    changelist_actions = ('sync_users_action_local',)
    actions_detail = ('resend_welcome_email_action',)

    def cleanup_no_ovpn_users(self, request):
        if request.method != "POST":
            return redirect('admin:vpn_panel_customuser_changelist')
            
        from .models import Client, CustomUser
        
        # 1. Collect users who don't have a linked Client or Client has no OVPN file
        # Safety: exclude superusers AND staff (admins)
        to_delete = CustomUser.objects.filter(
            vpn_client__has_ovpn_file=False
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
        
        if count > 0:
            messages.warning(request, f"Đã dọn dẹp {count} user không có file .ovpn.")
        else:
            messages.info(request, "Không tìm thấy user nào cần dọn dẹp.")
            
        return redirect('admin:vpn_panel_customuser_changelist')

    @admin.action(description='Đồng bộ từ VPN')
    def sync_users_action_local(self, request, queryset=None):
        created, skipped = VPNService.sync_system_users()
        messages.success(request, f"Đồng bộ hoàn tất: {created} mới, {skipped} đã tồn tại.")
        return redirect('admin:vpn_panel_customuser_changelist')

    def save_model(self, request, obj, form, change):
        is_new = obj.pk is None
        old_email = ""
        old_vpn_enabled = None
        
        if not is_new:
            old_inst = CustomUser.objects.get(pk=obj.pk)
            old_email = old_inst.email or ""
            old_vpn_enabled = old_inst.is_vpn_enabled

        if obj.email and (is_new or old_email != obj.email):
            # Generate random password BEFORE saving if new, so it's hashed correctly
            # OR after super().save_model and then save(update_fields=['password'])
            # Since AbstractUser has logic in save(), it's better to do it before
            # BUT if we do it before, super().save_model will save the hashed password
            # If we do it after, we need to save() again.
            
            # 1. Generate random password
            alphabet = string.ascii_letters + string.digits
            new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
            obj.set_password(new_password)
            # We don't save yet, super().save_model will do it.
        else:
            new_password = None

        super().save_model(request, obj, form, change)
        
        # Scenario: Admin creates a NEW user with email OR updates an existing email
        if obj.email and (is_new or old_email != obj.email):
            # Send welcome email (using the captured new_password) via Celery
            try:
                scheme = 'https' if request.is_secure() else 'http'
                site_url = f"{scheme}://{request.get_host()}"
                
                # Use on_commit to ensure task runs AFTER DB write is finished (fixes race condition)
                transaction.on_commit(lambda: send_welcome_email_task.delay(
                    obj.pk, 
                    new_password, 
                    site_url, 
                    (obj.is_staff or obj.is_superuser),
                    email=obj.email # Pass email as direct param as fallback for race condition
                ))
                
                messages.success(request, f"Đang gửi email thông tin tài khoản (với mật khẩu tự động: {new_password}) tới {obj.email} qua nền celery...")
            except Exception as e:
                messages.error(request, f"Lỗi lên lịch gửi email: {str(e)}")

        # If toggled or new, sync with system
        if is_new or old_vpn_enabled != obj.is_vpn_enabled:
            if hasattr(obj, 'vpn_client'):
                action = "unlock" if obj.is_vpn_enabled else "lock"
                ip = obj.vpn_client.ip_address or "0.0.0.0"
                VPNService.toggle_lock(obj.vpn_client.name, ip, action)
            
            if is_new:
                success, result = VPNService.add_client(obj.username)
                if success:
                    from .models import Client
                    client, _ = Client.objects.get_or_create(user=obj, defaults={'name': obj.username})
                    client.has_ovpn_file = True
                    client.save()
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

    @unfold_action(description='Gửi lại Email Chào mừng (Reset lại mật khẩu)')
    def resend_welcome_email_action(self, request, object_id):
        obj = self.get_object(request, object_id)
        # 1. Generate random password
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        obj.set_password(new_password)
        obj.save(update_fields=['password'])

        # 2. Schedule email task on commit
        try:
            scheme = 'https' if request.is_secure() else 'http'
            site_url = f"{scheme}://{request.get_host()}"
            
            transaction.on_commit(lambda: send_welcome_email_task.delay(
                obj.pk,
                new_password,
                site_url,
                (obj.is_staff or obj.is_superuser),
                email=obj.email # Fallback for race condition
            ))
            
            messages.success(request, f"Đang gửi lại email chào mừng tới {obj.email} (Mật khẩu mới: {new_password}) qua nền celery...")
        except Exception as e:
            messages.error(request, f"Lỗi lên lịch gửi: {str(e)}")
            
        return redirect('admin:vpn_panel_customuser_change', object_id)

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
        # 1. Check if we have a real-time IP (from cache or log)
        from .services import VPNService
        status_map = VPNService.get_client_status_map()
        if obj.username in status_map:
            active_ip = status_map[obj.username]
            return mark_safe(f'<span class="text-green-600 dark:text-green-400 font-bold">{active_ip}</span>')
            
        # 2. Fallback to DB
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

    def issue_ovpn_for_user(self, request, user_id):
        from .models import CustomUser, Client
        user = CustomUser.objects.get(pk=user_id)
        
        success, result = VPNService.add_client(user.username)
        if success:
            client, _ = Client.objects.get_or_create(user=user, defaults={'name': user.username})
            client.has_ovpn_file = True
            client.save()
            messages.success(request, f"Đã cấp phát file OVPN cho {user.username} thành công.")
        else:
            messages.error(request, f"Lỗi cấp phát: {result}")
            
        return redirect(request.META.get('HTTP_REFERER', 'admin:vpn_panel_customuser_changelist'))

    @admin.display(description='Hành động mật khẩu')
    def password_reset_link(self, obj):
        if obj.pk:
            url = reverse('admin:vpn_password_change', args=[obj.pk])
            return mark_safe(f'<a href="{url}" class="px-4 py-2 bg-primary-600 text-white rounded-lg font-bold no-underline inline-flex items-center gap-2 hover:bg-primary-700 transition-colors"><span class="material-symbols-outlined text-sm">lock_reset</span> Đổi mật khẩu ngay</a>')
        return "---"

    @admin.display(description='Hành động')
    def vpn_actions(self, obj):
        has_client = hasattr(obj, 'vpn_client')
        has_ovpn = False
        
        if has_client:
            # 1. Check DB flag
            if obj.vpn_client.has_ovpn_file:
                has_ovpn = True
            # 2. Check if user has an assigned IP (means they have a cert/ovpn)
            elif obj.vpn_client.ip_address:
                has_ovpn = True
                obj.vpn_client.has_ovpn_file = True
                obj.vpn_client.save(update_fields=['has_ovpn_file'])
            # 3. Check disk as last resort
            else:
                ovpn_path = settings.VPN_SETTINGS['OVPN_OUT_DIR'] / f"{obj.username}.ovpn"
                if ovpn_path.exists():
                    has_ovpn = True
                    obj.vpn_client.has_ovpn_file = True
                    obj.vpn_client.save(update_fields=['has_ovpn_file'])
        
        is_sys_locked = VPNService.is_user_locked(obj.username)
        
        # If DB says disabled OR system says locked -> Button should be "Mở"
        needs_unlock = not obj.is_vpn_enabled or is_sys_locked
        
        # Toggle Lock Button
        lock_url = reverse('admin:vpn_toggle_lock', args=[obj.pk])
        lock_btn_text = "✅ Mở" if needs_unlock else "🔒 Khóa"
        lock_btn_color = "bg-green-600 hover:bg-green-700" if needs_unlock else "bg-red-600 hover:bg-red-700"
        
        if has_ovpn:
            otp_url = reverse('admin_generate_user_otp', args=[obj.pk])
            download_url = reverse('download_ovpn', args=[obj.vpn_client.pk])
            return mark_safe(f'''
                <div class="flex gap-2">
                    <a class="px-2 py-1 bg-blue-600 text-white rounded text-xs hover:bg-blue-700 no-underline cursor-pointer" onclick="generateOTP('{reverse('admin_generate_user_otp_api', args=[obj.pk])}', '{obj.username}')">🔑 OTP</a>
                    <a class="px-2 py-1 bg-indigo-600 text-white rounded text-xs hover:bg-indigo-700 no-underline" href="{download_url}">📥 OVPN</a>
                    <a class="px-2 py-1 {lock_btn_color} text-white rounded text-xs no-underline" href="{lock_url}">{lock_btn_text}</a>
                    <a class="px-2 py-1 bg-gray-600 text-white rounded text-xs hover:bg-gray-700 no-underline" href="{reverse('admin:vpn_password_change', args=[obj.pk])}">🔑 Pass</a>
                </div>
            ''')
        else:
            issue_url = reverse('admin:vpn_issue_ovpn', args=[obj.pk])
            return mark_safe(f'''
                <div class="flex gap-2">
                    <a class="px-2 py-1 bg-orange-500 text-white rounded text-xs hover:bg-orange-600 no-underline flex items-center gap-1" href="{issue_url}">
                        <span class="material-symbols-outlined text-sm">add_circle</span> Cấp phát OVPN
                    </a>
                    <a class="px-2 py-1 {lock_btn_color} text-white rounded text-xs no-underline" href="{lock_url}">{lock_btn_text}</a>
                </div>
            ''')

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<path:user_id>/toggle-lock/', self.admin_site.admin_view(self.toggle_vpn_lock), name='vpn_toggle_lock'),
            path('<path:user_id>/issue-ovpn/', self.admin_site.admin_view(self.issue_ovpn_for_user), name='vpn_issue_ovpn'),
            path('<path:user_id>/password-change/', self.admin_site.admin_view(self.admin_password_change_view), name='vpn_password_change'),
            path('global-reset/', self.admin_site.admin_view(self.global_reset_rules), name='vpn_global_reset'),
            path('cleanup-no-ovpn/', self.admin_site.admin_view(self.cleanup_no_ovpn_users), name='vpn_cleanup_no_ovpn'),
        ]
        return custom_urls + urls

    def global_reset_rules(self, request):
        """Action to unlock everyone and flush ALL stale firewall rules (including legacy ones)."""
        from vpn_panel.models import Client
        
        # 1. Flush legacy chain if it exists
        VPNService.run_command(["sudo", "iptables", "-F", "VPN_CONTROL"])
        
        # 2. Sequential unlock for all known IPs in FORWARD
        clients = Client.objects.all()
        for client in clients:
            if client.ip_address:
                VPNService.toggle_lock(client.name, client.ip_address, "unlock")
        
        messages.success(request, f"Đã thực hiện Reset toàn bộ tường lửa (bao gồm cả phân tách cũ) cho {clients.count()} clients.")
        return redirect(request.META.get('HTTP_REFERER', 'admin:vpn_panel_customuser_changelist'))

    def toggle_vpn_lock(self, request, user_id):
        user = CustomUser.objects.get(pk=user_id)
        current_state = user.is_vpn_enabled
        user.is_vpn_enabled = not current_state
        
        # We rely on CustomUser.save() to handle:
        # 1. Adding days if unlocking (in models.py)
        # 2. Calling VPNService.toggle_lock with the latest IP
        user.save()
        
        action_name = "KHÓA" if current_state else "MỞ KHÓA"
        messages.success(request, f"Đã {action_name} thành công tài khoản {user.username}.")
        print(f"DEBUG: Admin action success message added for {user.username}")
        
        # Prefer referring page, fallback to changelist, then to index
        next_url = request.META.get('HTTP_REFERER')
        if not next_url or 'toggle-lock' in next_url:
            next_url = reverse('admin:vpn_panel_customuser_changelist')
            
        return redirect(next_url)
    def admin_password_change_view(self, request, user_id):
        user = CustomUser.objects.get(pk=user_id)
        if request.method == 'POST':
            new_password = request.POST.get('password')
            if new_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, f"Đã đổi mật khẩu cho {user.username} thành công.")
                return redirect('admin:vpn_panel_customuser_changelist')
        
        context = {
            **self.admin_site.each_context(request),
            'title': f'Đổi mật khẩu: {user.username}',
            'target_user': user,
            'opts': self.model._meta, # Added to fix KeyError in Unfold template
        }
        return TemplateResponse(request, "admin/password_change.html", context)

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
                client, _ = Client.objects.get_or_create(user=obj, defaults={'name': obj.username})
                client.has_ovpn_file = True
                client.save()
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
        for user in queryset:
            user.is_vpn_enabled = False
            user.save()
            # Task handles notification and firewall
        messages.warning(request, f"Đã gửi yêu cầu khóa {queryset.count()} tài khoản.")

    @admin.action(description='Mở khóa VPN & Thêm ngày dùng')
    def unlock_vpn_action(self, request, queryset):
        days = int(VPNService.get_vpn_setting('UNLOCK_FREE_DAYS', '3'))
        for user in queryset:
            user.is_vpn_enabled = True
            
            # NEW: Add X days
            if user.expiry_date:
                user.expiry_date += timedelta(days=days)
            else:
                user.expiry_date = timezone.now().date() + timedelta(days=days)
                
            user.save()
            # Task handles notification and firewall via on_commit in model.save()
        
        messages.success(request, f"Đã gửi yêu cầu mở khóa và cộng {days} ngày cho {queryset.count()} tài khoản.")

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
    list_display = ('key', 'display_value', 'description')
    search_fields = ('key', 'description', 'value')
    # Removed list_editable for description as requested
    
    @admin.display(description=_("Value"))
    def display_value(self, obj):
        if len(obj.value) > 60:
            return obj.value[:60] + "..."
        return obj.value
    
    @admin.display(description=_("Value"))
    def display_value(self, obj):
        if len(obj.value) > 100:
            return obj.value[:100] + "..."
        return obj.value

    fieldsets = (
        (None, {
            'fields': (('key',), 'value', 'description'),
            'classes': ('wide',),
        }),
    )

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

from unfold.contrib.forms.widgets import WysiwygWidget

@admin.register(Announcement)
class AnnouncementAdmin(ModelAdmin):
    list_display = ('subject', 'sent_at', 'recipients_count', 'send_button')
    readonly_fields = ('sent_at', 'recipients_count')
    formfield_overrides = {
        models.TextField: {
            "widget": WysiwygWidget,
        }
    }
    actions = ['send_announcement_action']

    @admin.display(description='Hành động')
    def send_button(self, obj):
        if obj.pk:
            url = reverse('admin:vpn_send_announcement', args=[obj.pk])
            return mark_safe(f'<a href="{url}" class="px-2 py-1 bg-primary-600 text-white rounded text-xs no-underline hover:bg-primary-700">🚀 Gửi ngay</a>')
        return "---"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<path:announcement_id>/send/', self.admin_site.admin_view(self.trigger_send_announcement), name='vpn_send_announcement'),
        ]
        return custom_urls + urls

    def trigger_send_announcement(self, request, announcement_id):
        from .tasks import send_bulk_announcement, send_welcome_email_task
        send_bulk_announcement.delay(announcement_id)
        messages.success(request, "Đã bắt đầu gửi thông báo tới toàn bộ người dùng qua Celery.")
        return redirect('admin:vpn_panel_announcement_changelist')

    @admin.action(description='Gửi thông báo tới toàn bộ USERS')
    def send_announcement_action(self, request, queryset):
        for ann in queryset:
            send_bulk_announcement.delay(ann.pk)
        messages.success(request, f"Đã hàng đợi gửi {queryset.count()} thông báo.")

@admin.register(TaskLog)
class TaskLogAdmin(ModelAdmin):
    list_display = ('task_name', 'status', 'started_at', 'duration', 'result_short')
    list_filter = ('status', 'task_name')
    readonly_fields = ('task_name', 'status', 'result', 'error', 'started_at', 'finished_at')
    
    @admin.display(description='Kết quả')
    def result_short(self, obj):
        res = obj.result or obj.error
        if res and len(res) > 80:
            return res[:80] + "..."
        return res

@admin.register(TaskControl)
class TaskControlAdmin(ModelAdmin):
    def has_add_permission(self, request): return False
    def has_delete_permission(self, request, obj=None): return False
    
    def changelist_view(self, request, extra_context=None):
        from .models import TaskLog
        from .tasks import run_system_task_exec
        
        if request.method == 'POST':
            task_type = request.POST.get('task_type')
            if task_type:
                # Run the task through the wrapper
                run_system_task_exec.delay(task_type)
                messages.success(request, f"Đã bắt đầu tác vụ '{task_type}' trong nền... Kiểm tra nhật ký bên dưới để xem kết quả.")
            return redirect('admin:vpn_panel_taskcontrol_changelist')

        context = {
            **self.admin_site.each_context(request),
            'title': 'Điều khiển & Gỡ lỗi Hệ thống',
            'logs': TaskLog.objects.all()[:30], # Show last 30 logs
        }
        return TemplateResponse(request, "admin/task_control.html", context)

@admin.register(SystemLog)
class SystemLogAdmin(ModelAdmin):
    def has_add_permission(self, request): return False
    def has_delete_permission(self, request, obj=None): return False
    
    def changelist_view(self, request, extra_context=None):
        from .services import VPNService
        
        # Consistent log fetching for all services
        log_contents = {
            'openvpn': VPNService.get_service_logs('openvpn', lines=100),
            'panel_err': VPNService.get_service_logs('panel', lines=100),
            'worker_err': VPNService.get_service_logs('worker', lines=100),
            'beat_err': VPNService.get_service_logs('beat', lines=100),
        }

        context = {
            **self.admin_site.each_context(request),
            'title': 'Nhật ký Hệ thống (Real-time Errors)',
            'log_contents': log_contents,
        }
        return TemplateResponse(request, "admin/system_logs.html", context)

@admin.register(InstallerFile)
class InstallerFileAdmin(ModelAdmin):
    list_display = ('file', 'uploaded_at')

@admin.register(InstallerManager)
class InstallerManagerAdmin(ModelAdmin):
    def has_add_permission(self, request): return False
    def has_delete_permission(self, request, obj=None): return False
    
    def changelist_view(self, request, extra_context=None):
        from .services import VPNService
        import os
        from django.core.files.storage import default_storage
        
        if request.method == 'POST':
            action = request.POST.get('action')
            filename = request.POST.get('filename')
            
            if action == 'upload' and request.FILES.get('file'):
                f = request.FILES['file']
                # Create DB record (which also saves file via FileField)
                inst = InstallerFile.objects.create(file=f)
                messages.success(request, f"Đã tải lên tệp: {inst.file.name}")
                
            elif action == 'set_win' and filename:
                VPNService.set_vpn_setting('INSTALLER_WIN_NAME', filename)
                messages.success(request, f"Đã đặt {filename} làm bộ cài Windows mặc định.")
                
            elif action == 'set_mac' and filename:
                VPNService.set_vpn_setting('INSTALLER_MAC_NAME', filename)
                messages.success(request, f"Đã đặt {filename} làm bộ cài macOS mặc định.")
                
            elif action == 'set_linux' and filename:
                VPNService.set_vpn_setting('INSTALLER_LINUX_NAME', filename)
                messages.success(request, f"Đã đặt {filename} làm bộ cài Linux mặc định.")
                
            elif action == 'delete' and filename:
                # Delete from DB if exists, which also triggers physical deletion via our model override
                InstallerFile.objects.filter(file__contains=filename).delete()
                # Manual physical delete as fallback/safety for files without DB record
                phys_path = settings.BASE_DIR / 'static' / 'openvpn_installer' / filename
                if phys_path.exists():
                    os.remove(phys_path)
                messages.warning(request, f"Đã xóa vĩnh viễn tệp {filename}")
                
            return redirect('admin:vpn_panel_installermanager_changelist')

        context = {
            **self.admin_site.each_context(request),
            'title': 'Quản lý Bộ cài đặt',
            'files': VPNService.get_available_installers(),
            'current_win': VPNService.get_vpn_setting('INSTALLER_WIN_NAME'),
            'current_mac': VPNService.get_vpn_setting('INSTALLER_MAC_NAME'),
            'current_linux': VPNService.get_vpn_setting('INSTALLER_LINUX_NAME'),
        }
        return TemplateResponse(request, "admin/installer_manager.html", context)
