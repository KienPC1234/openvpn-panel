from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView, ListView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views import View
from django.http import HttpResponse, FileResponse
from django.urls import reverse
from django.conf import settings
from .forms import RegistrationForm
from django.contrib.auth import login as auth_login
from django.db.models import Q
from django.contrib import messages
import secrets, os
from datetime import timedelta
from django.utils import timezone
from .models import Client, CustomUser, OTPCode, Setting
from .services import VPNService
import os

class RegisterView(CreateView):
    model = CustomUser
    form_class = RegistrationForm
    template_name = 'register.html'
    success_url = '/dashboard/'

    def form_valid(self, form):
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        user.save()
        # Automatically create VPN client in system and database
        success, result = VPNService.add_client(user.username)
        if success:
            Client.objects.get_or_create(name=result, user=user)
        auth_login(self.request, user)
        return redirect(self.success_url)

class DashboardView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        if user.is_staff and request.GET.get('force_admin'):
            return redirect('admin:index')
            
        if user.requires_profile_update:
            return redirect('profile_update')
        
        usage = user.usage_logs.first()
        return render(request, 'dashboard.html', {
            'user_profile': user,
            'usage': usage,
            'remaining_days': user.remaining_days
        })

class ProfileUpdateView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'profile_update.html')

    def post(self, request):
        user = request.user
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not email or not password or password != confirm_password:
            return render(request, 'profile_update.html', {'error': 'Invalid data or passwords do not match'})

        user.email = email
        user.set_password(password)
        user.requires_profile_update = False
        user.save()
        
        # Ensure VPN client exists for the user
        if not hasattr(user, 'vpn_client'):
            success, result = VPNService.add_client(user.username)
            if success:
                Client.objects.get_or_create(name=result, user=user)

        auth_login(request, user) # Re-login after password change
        return redirect('dashboard')

# ... other views remain, just ensure they use correct models ...

class ClientsPartialView(LoginRequiredMixin, View):
    def get(self, request):
        clients = Client.objects.all()
        return render(request, 'partials/client_list.html', {'clients': clients})

class StatsPartialView(LoginRequiredMixin, View):
    def get(self, request):
        status = VPNService.get_service_status()
        stats = VPNService.get_network_interfaces()
        active_count = len(VPNService.get_online_users())
        history = VPNService.get_traffic_history(limit=30)
        
        user_usage = VPNService.get_per_user_usage()
        total_rx = sum(u['rx'] for u in user_usage.values())
        total_tx = sum(u['tx'] for u in user_usage.values())
        
        return render(request, 'partials/stats.html', {
            'service_status': status,
            'network_stats': stats,
            'active_users': active_count,
            'total_vpn_rx': VPNService.format_bytes(total_rx),
            'total_vpn_tx': VPNService.format_bytes(total_tx),
            'traffic_history': history
        })

class AddClientView(LoginRequiredMixin, View):
    def post(self, request):
        name = request.POST.get('name')
        if name:
            success, result = VPNService.add_client(name)
            if success:
                Client.objects.get_or_create(name=result)
        return redirect('clients_partial')

class DeleteClientView(LoginRequiredMixin, View):
    def delete(self, request, pk):
        client = get_object_or_404(Client, pk=pk)
        VPNService.delete_client(client.name)
        client.delete()
        return redirect('clients_partial')

class ToggleLockView(LoginRequiredMixin, View):
    def post(self, request, pk):
        client = get_object_or_404(Client, pk=pk)
        action = "unlock" if client.is_locked else "lock"
        # In a real scenario, we'd need the client's current IP
        ip = client.ip_address or "0.0.0.0" 
        success, msg = VPNService.toggle_lock(client.name, ip, action)
        if success:
            client.is_locked = not client.is_locked
            client.save()
        return redirect('clients_partial')

class DownloadOvpnView(LoginRequiredMixin, View):
    def get(self, request, pk):
        client = get_object_or_404(Client, pk=pk)
        file_path = settings.VPN_SETTINGS['OVPN_OUT_DIR'] / f"{client.name}.ovpn"
        if file_path.exists():
            return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=f"{client.name}.ovpn")
        return HttpResponse("File not found", status=404)

class OTPDownloadView(View):
    def get(self, request):
        return render(request, 'otp_download.html')

    def post(self, request):
        otp_code = request.POST.get('otp')
        otp = OTPCode.objects.filter(code=otp_code, is_used=False, expires_at__gt=timezone.now()).first()
        if otp and otp.user and hasattr(otp.user, 'vpn_client'):
            client = otp.user.vpn_client
            file_path = settings.VPN_SETTINGS['OVPN_OUT_DIR'] / f"{client.name}.ovpn"
            if file_path.exists():
                otp.is_used = True
                otp.save()
                return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=f"{client.name}.ovpn")
        messages.error(request, "Mã OTP không hợp lệ hoặc đã hết hạn.")
        return redirect('otp_download')

class InstallerView(View):
    def get(self, request):
        installer_dir = settings.BASE_DIR / 'static' / 'openvpn_installer'
        installers = []
        if installer_dir.exists():
            for f in os.listdir(installer_dir):
                if os.path.isfile(installer_dir / f):
                    label = "Windows (x64)" if "amd64" in f.lower() or "win" in f.lower() else "macOS" if "macos" in f.lower() or "dmg" in f.lower() else f
                    icon = "fa-windows" if "win" in label.lower() else "fa-apple" if "macos" in label.lower() else "fa-download"
                    installers.append({
                        'name': f,
                        'label': label,
                        'icon': icon,
                        'url': settings.STATIC_URL + 'openvpn_installer/' + f,
                        'size': f"{os.path.getsize(installer_dir / f) / (1024*1024):.2f} MB"
                    })
        return render(request, 'installer_download.html', {'installers': installers})

class StaffRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_staff

class AdminGenerateOTPView(LoginRequiredMixin, StaffRequiredMixin, View):
    def get(self, request, pk):
        user = get_object_or_404(CustomUser, pk=pk)
        length = int(VPNService.get_vpn_setting('OTP_CODE_LENGTH', '8'))
        code = ''.join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(length))
        OTPCode.objects.create(user=user, code=code)
        messages.success(request, f"Mã OTP cho {user.username}: {code}")
        return redirect('admin:vpn_panel_customuser_changelist')

class RestartServiceView(LoginRequiredMixin, StaffRequiredMixin, View):
    def post(self, request):
        VPNService.run_command(["systemctl", "restart", settings.VPN_SETTINGS['SERVICE_NAME']])
        messages.success(request, "Services restarted successfully.")
        return redirect('dashboard')

from .forms import AdminUserCreationForm

class AdminUserManageView(LoginRequiredMixin, UserPassesTestMixin, View):
    def test_func(self):
        return self.request.user.is_staff

    def get(self, request):
        users = CustomUser.objects.exclude(is_superuser=True).order_by('-id')
        form = AdminUserCreationForm()
        return render(request, 'admin/user_manage.html', {
            'users': users,
            'form': form
        })

    def post(self, request):
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Đã tạo tài khoản mới thành công!")
            return redirect('admin_user_manage')
        
        users = CustomUser.objects.exclude(is_superuser=True).order_by('-id')
        return render(request, 'admin/user_manage.html', {
            'users': users,
            'form': form
        })

class AdminUserDeleteView(LoginRequiredMixin, UserPassesTestMixin, View):
    def test_func(self):
        return self.request.user.is_staff

    def post(self, request, pk):
        user = get_object_or_404(CustomUser, pk=pk)
        if not user.is_superuser:
            username = user.username
            user.delete()
            messages.warning(request, f"Đã xóa tài khoản {username}")
        return redirect('admin_user_manage')

class AdminUserToggleLockView(LoginRequiredMixin, UserPassesTestMixin, View):
    def test_func(self):
        return self.request.user.is_staff
    
    def post(self, request, pk):
        user = get_object_or_404(CustomUser, pk=pk)
        if not user.is_superuser:
            user.is_vpn_enabled = not user.is_vpn_enabled
            user.save()
            
            # Also toggle system lock
            if hasattr(user, 'vpn_client'):
                # Try to get the LATEST IP from status log instead of relying on stale DB
                status_map = VPNService.get_client_status_map()
                current_ip = status_map.get(user.vpn_client.name)
                
                if current_ip:
                    user.vpn_client.ip_address = current_ip
                    user.vpn_client.save()
                
                ip = user.vpn_client.ip_address or "0.0.0.0"
                action = "unlock" if user.is_vpn_enabled else "lock"
                VPNService.toggle_lock(user.vpn_client.name, ip, action)
            
            status = "MỞ" if user.is_vpn_enabled else "KHÓA"
            messages.success(request, f"Đã {status} tài khoản {user.username}")
        return redirect('admin_user_manage')

class LockedView(View):
    def get(self, request):
        qr_setting = Setting.objects.filter(key='PORTAL_QR_CODE').first()
        group_setting = Setting.objects.filter(key='PORTAL_GROUP_LINK').first()
        
        # Fallback to static if no setting
        qr_path = qr_setting.value if (qr_setting and qr_setting.value) else VPNService.get_vpn_setting('PORTAL_QR_FALLBACK', "/static/images/qr.png")
        group_link = group_setting.value if group_setting else None
        
        logo = VPNService.get_vpn_setting('PORTAL_LOGO', "/static/images/logo.png")
        
        return render(request, 'locked.html', {
            'qr_code': qr_path,
            'group_link': group_link,
            'logo': logo
        })

class PortalRedirectView(View):
    """Redirects all captive portal probes to the locked page"""
    def get(self, request):
        return redirect('locked')

class PortalSuccessView(View):
    """Fallback success for probes that don't need redirect"""
    def get(self, request):
        from django.http import HttpResponse
        return HttpResponse("Blocked", content_type="text/plain")

class AdminServiceLogView(LoginRequiredMixin, StaffRequiredMixin, View):
    def get(self, request):
        from django.contrib import admin
        context = {
            **admin.site.each_context(request),
            'title': 'Service Logs',
        }
        return render(request, 'admin/vpn_logs.html', context)

class AdminServiceLogContent(LoginRequiredMixin, StaffRequiredMixin, View):
    def get(self, request):
        logs = VPNService.get_service_logs(lines=100)
        return HttpResponse(f"<pre class='font-mono text-sm text-blue-400 dark:text-blue-300 whitespace-pre-wrap leading-relaxed m-0'>{logs}</pre>")
