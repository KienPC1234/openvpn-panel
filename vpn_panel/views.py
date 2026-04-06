from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView, ListView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views import View
from django.http import HttpResponse, FileResponse, JsonResponse
from django.urls import reverse
from django.conf import settings
from .forms import RegistrationForm
from django.contrib.auth import login as auth_login
from django.db.models import Q
from django.contrib import messages
from django.core.mail import send_mail
import base64, requests
import secrets, os, random, logging
from datetime import timedelta
from django.utils import timezone
from .models import Client, CustomUser, OTPCode, Setting
from .services import VPNService
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


def _send_register_otp(email, otp_code):
    """Send OTP email for registration verification using HTML template."""
    subject = "Mã xác thực tài khoản VPN Manager"
    site_name = VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
    admin_email = VPNService.get_vpn_setting('ADMIN_EMAIL', settings.DEFAULT_FROM_EMAIL)
    admin_phone = VPNService.get_vpn_setting('ADMIN_PHONE', 'N/A')
    
    message_body = f"Chào mừng bạn đến với {site_name}! Mã xác thực OTP của bạn là:\n\n{otp_code}\n\nMã có hiệu lực trong 10 phút. Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email."
    
    html_content = render_to_string('emails/notification_email.html', {
        'subject': subject,
        'user_name': email,
        'message_body': message_body,
        'site_name': site_name,
        'support_email': admin_email,
        'support_phone': admin_phone,
    })
    
    try:
        send_mail(
            subject,
            f"Mã OTP của bạn là: {otp_code}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            html_message=html_content,
            fail_silently=False
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {e}")
        return False


from django.contrib.staticfiles import finders

def get_image_base64(path):
    """Converts a local static image to a base64 data URI."""
    if not path or path.startswith('data:'):
        return path
        
    try:
        # Clean the path for searching
        search_path = path
        if path.startswith('/static/'):
            search_path = path.replace('/static/', '', 1)
        
        # 1. Try Django's builtin finders (best for dev and multi-app static)
        full_path = finders.find(search_path)
        
        if not full_path:
            # 2. Fallback to manual check in project-wide folders
            locs = [
                os.path.join(settings.BASE_DIR, 'static', search_path),
                os.path.join(settings.BASE_DIR, 'staticfiles', search_path), # production static
                os.path.join(settings.BASE_DIR, 'theme/static', search_path),
            ]
            for loc in locs:
                if os.path.exists(loc):
                    full_path = loc
                    break
                    
        if full_path and os.path.exists(full_path):
            with open(full_path, "rb") as image_file:
                ext = os.path.splitext(full_path)[1].lower().replace('.', '')
                if ext == 'jpg': ext = 'jpeg'
                elif ext == 'svg': ext = 'svg+xml'
                
                content = image_file.read()
                if not content:
                    logger.warning(f"Static file {full_path} is empty.")
                    return path
                    
                encoded_string = base64.b64encode(content).decode('utf-8')
                return f"data:image/{ext};base64,{encoded_string}"
        else:
            logger.warning(f"Static file NOT found for base64 encoding: {path}")
            
    except Exception as e:
        logger.error(f"Error encoding image to base64 for path {path}: {str(e)}")
        
    return path


def _verify_recaptcha(request):
    """Verify Google reCAPTCHA v2 token."""
    token = request.POST.get('g-recaptcha-response')
    if not token:
        logger.warning("reCAPTCHA token missing in request.")
        return False
        
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': settings.RECAPTCHA_SECRET_KEY,
                'response': token
            },
            timeout=10
        )
        result = response.json()
        success = result.get('success', False)
        if not success:
            logger.warning(f"reCAPTCHA verification failed: {result.get('error-codes')}")
        return success
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {e}")
        # In case of network error, we might want to fail-safe or fail-strict.
        # Failing strict for security.
        return False


from django.contrib.auth.views import LoginView as DjangoLoginView

class CustomLoginView(DjangoLoginView):
    template_name = 'login.html'
    
    def post(self, request, *args, **kwargs):
        if not _verify_recaptcha(request):
            messages.error(request, 'Xác thực reCAPTCHA thất bại. Vui lòng thử lại.')
            return self.get(request, *args, **kwargs)
        return super().post(request, *args, **kwargs)


class RegisterView(View):
    template_name = 'register.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard')
        form = RegistrationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard')
            
        # reCAPTCHA Check
        if not _verify_recaptcha(request):
            messages.error(request, 'Xác thực reCAPTCHA thất bại. Vui lòng thử lại.')
            form = RegistrationForm(request.POST)
            return render(request, self.template_name, {'form': form})
            
        form = RegistrationForm(request.POST)

        # Make email required for registration
        if not request.POST.get('email', '').strip():
            form.add_error('email', 'Email là bắt buộc để xác thực tài khoản.')

        if form.is_valid():
            data = form.cleaned_data
            email = data['email'].strip().lower()

            # Check username uniqueness
            if CustomUser.objects.filter(username=data['username']).exists():
                form.add_error('username', 'Tên đăng nhập này đã được sử dụng.')
                return render(request, self.template_name, {'form': form})

            # Check email uniqueness
            if CustomUser.objects.filter(email=email).exists():
                form.add_error('email', 'Email này đã được đăng ký.')
                return render(request, self.template_name, {'form': form})

            # Generate 6-digit OTP using CSRNG
            otp_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])

            # Store registration data in session (not in DB yet)
            request.session['pending_registration'] = {
                'username': data['username'],
                'password': data['password'],
                'email': email,
                'full_name': data.get('full_name', ''),
                'otp': otp_code,
                'expires': (timezone.now() + timedelta(minutes=10)).isoformat(),
            }

            # Send OTP email
            sent = _send_register_otp(email, otp_code)
            if not sent:
                # If email fails, create account anyway (for dev/no-email setups)
                messages.warning(request, 'Không thể gửi email OTP. Hãy liên hệ quản trị viên.')

            return redirect('verify_register_otp')

        return render(request, self.template_name, {'form': form})


class VerifyRegisterOTPView(View):
    template_name = 'verify_register_otp.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard')
        reg = request.session.get('pending_registration')
        if not reg:
            messages.error(request, 'Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.')
            return redirect('register')
        return render(request, self.template_name, {'email': reg.get('email', '')})

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard')

        reg = request.session.get('pending_registration')
        if not reg:
            messages.error(request, 'Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.')
            return redirect('register')

        otp_input = request.POST.get('otp', '').strip()
        email = reg.get('email', '')

        # Check expiry
        from dateutil import parser as dateparser
        expires = dateparser.parse(reg['expires'])
        if timezone.now() > expires:
            del request.session['pending_registration']
            return render(request, self.template_name, {
                'email': email,
                'error': 'Mã OTP đã hết hạn. Vui lòng đăng ký lại.'
            })

        # Validate OTP
        expected_otp = reg.get('otp')
        logger.info(f"Verifying OTP for {email}: Received='{otp_input}', Expected='{expected_otp[:2]}****'")

        if otp_input != expected_otp:
            logger.warning(f"OTP Mismatch for {email}: Input='{otp_input}', Expected='{expected_otp}'")
            return render(request, self.template_name, {
                'email': email,
                'error': f'Mã OTP không đúng. Vui lòng thử lại.'
            })

        # OTP correct → Create user
        try:
            from django.db import transaction, IntegrityError
            with transaction.atomic():
                free_days = int(VPNService.get_vpn_setting('UNLOCK_FREE_DAYS', '1'))
                user = CustomUser(
                    username=reg['username'],
                    email=reg['email'],
                    full_name=reg.get('full_name', ''),
                    purchase_date=timezone.now().date(),
                    duration_days=free_days,
                    status='ACTIVE',
                    is_vpn_enabled=True,
                )
                user.set_password(reg['password'])
                try:
                    user.save()
                except IntegrityError:
                    return render(request, self.template_name, {
                        'email': email,
                        'error': 'Tên đăng nhập hoặc Email này đã bị người khác đăng ký. Vui lòng đăng ký lại.'
                    })

                # --- Welcome Email via Celery ---
                try:
                    from .tasks import send_welcome_email_task
                    scheme = 'https' if request.is_secure() else 'http'
                    site_url = f"{scheme}://{request.get_host()}"
                    
                    # Use on_commit safely since we are inside transaction.atomic()
                    transaction.on_commit(lambda: send_welcome_email_task.delay(
                        user.pk,
                        reg['password'], 
                        site_url,
                        False, # public user, not admin
                        email=user.email # Pass email directly as fallback
                    ))
                except Exception as e:
                    logger.error(f"Failed to schedule register welcome email: {e}")

                # Create VPN client
                success, result = VPNService.add_client(user.username)
                if success:
                    client, _ = Client.objects.get_or_create(user=user, defaults={'name': result})
                    client.has_ovpn_file = True
                    client.save()

            # Clear session after successful transaction
            del request.session['pending_registration']

            # Log user in
            auth_login(request, user)
            messages.success(request, f'🎉 Chào mừng! Tài khoản đã được xác thực. Bạn có {free_days} ngày dùng thử miễn phí!')
            return redirect('dashboard')

        except Exception as e:
            logger.error(f"Error creating user in OTP verification: {e}")
            return render(request, self.template_name, {
                'email': email,
                'error': f'Có lỗi xảy ra khi tạo tài khoản: {str(e)}'
            })

class DashboardView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        if user.is_staff and request.GET.get('force_admin'):
            return redirect('admin:index')
            
        if user.requires_profile_update:
            return redirect('profile_update')
        
        usage = user.usage_logs.first()
        if not usage:
            # Fallback to realtime if DB log is empty
            real_usage = VPNService.get_per_user_usage().get(user.username)
            if real_usage:
                usage = type('obj', (object,), {'bytes_received': real_usage['rx'], 'bytes_sent': real_usage['tx']})

        # Get QR code for payment if locked/expired
        qr_setting = Setting.objects.filter(key='PORTAL_QR_CODE').first()
        qr_path = qr_setting.value if (qr_setting and qr_setting.value) else VPNService.get_vpn_setting('PORTAL_QR_FALLBACK', "/static/images/qr.png")
        qr_code = get_image_base64(qr_path)

        return render(request, 'dashboard.html', {
            'user_profile': user,
            'usage': usage,
            'remaining_days': user.remaining_days,
            'qr_code': qr_code,
            'status_text': user.status_text
        })

class ProfileUpdateView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'profile_update.html')

    def post(self, request):
        user = request.user
        email = request.POST.get('email')
        full_name = request.POST.get('full_name')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not email:
            messages.error(request, 'Email là bắt buộc để quản lý tài khoản.')
            return render(request, 'profile_update.html')

        # Check for password update
        if password:
            old_password = request.POST.get('old_password')
            if not user.check_password(old_password):
                messages.error(request, 'Mật khẩu cũ không chính xác.')
                return render(request, 'profile_update.html')
                
            if password != confirm_password:
                messages.error(request, 'Mật khẩu mới không khớp.')
                return render(request, 'profile_update.html')
            user.set_password(password)
            auth_login(request, user) # Re-login after password change

        user.email = email
        if full_name is not None:
            user.full_name = full_name
            
        was_locked = user.requires_profile_update
        user.requires_profile_update = False
        user.save()
        
        # --- Welcome Email (Only if it was a setup/lock) ---
        if was_locked:
            try:
                from .tasks import send_welcome_email_task
                scheme = 'https' if request.is_secure() else 'http'
                site_url = f"{scheme}://{request.get_host()}"
                
                # Pass plain pass only if just changed
                email_pass = password if password else "******** (Đã giữ nguyên)"
                
                # Use celery task
                from django.db import transaction
                transaction.on_commit(lambda: send_welcome_email_task.delay(
                    user.pk,
                    email_pass, 
                    site_url,
                    False, # not admin
                    email=user.email
                ))
                logger.info(f"Welcome email scheduled for {user.email}")
            except Exception as e:
                logger.error(f"Failed to schedule welcome email: {e}")
        
        # Ensure VPN client exists for the user (in case of manual import)
        if not hasattr(user, 'vpn_client'):
            success, result = VPNService.add_client(user.username)
            if success:
                Client.objects.get_or_create(name=result, user=user)

        messages.success(request, 'Thông tin tài khoản đã được cập nhật thành công!')
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
        otp_input = request.POST.get('otp', '').strip()
        if not otp_input:
            messages.error(request, "Vui lòng nhập mã OTP.")
            return redirect('otp_download')

        # Use iexact for case-insensitive matching if the code is just alphanumeric
        otp = OTPCode.objects.filter(code__iexact=otp_input, is_used=False).first()
        
        if not otp:
            messages.error(request, "Mã OTP không hợp lệ.")
            return redirect('otp_download')
            
        if not otp.is_valid():
             messages.error(request, "Mã OTP này đã hết hạn.")
             return redirect('otp_download')

        if otp.user and hasattr(otp.user, 'vpn_client'):
            client = otp.user.vpn_client
            file_path = settings.VPN_SETTINGS['OVPN_OUT_DIR'] / f"{client.name}.ovpn"
            
            if file_path.exists():
                otp.is_used = True
                otp.save()
                return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=f"{client.name}.ovpn")
            else:
                logger.error(f"OTP valid but OVPN file NOT found for {client.name} at {file_path}")
                messages.error(request, "Lỗi hệ thống: Không tìm thấy tệp cấu hình trên máy chủ. Vui lòng liên hệ Admin.")
        else:
            messages.error(request, "Mã OTP không liên kết với tài khoản VPN hợp lệ.")
            
        return redirect('otp_download')

class InstallerView(View):
    def get(self, request):
        installer_dir = settings.BASE_DIR / 'static' / 'openvpn_installer'
        installers = []
        
        # 1. Try to get specific settings first
        win_name = VPNService.get_vpn_setting('INSTALLER_WIN_NAME')
        mac_name = VPNService.get_vpn_setting('INSTALLER_MAC_NAME')
        linux_name = VPNService.get_vpn_setting('INSTALLER_LINUX_NAME')
        
        # 2. Helper to add installer info
        def add_installer(filename, label_preset=None):
            file_path = installer_dir / filename
            if not file_path.exists() or not file_path.is_file():
                return False
                
            label = label_preset
            if not label:
                f_low = filename.lower()
                if any(x in f_low for x in ["amd64", "win", "x64", ".msi", ".exe"]):
                    label = "Windows (x64)"
                elif any(x in f_low for x in ["macos", "dmg", ".pkg", "apple"]):
                    label = "macOS"
                else:
                    label = filename
                
            icon = "fa-windows" if "win" in label.lower() else "fa-apple" if "macos" in label.lower() else "fa-download"
            
            # Avoid duplicate files
            if any(i['name'] == filename for i in installers):
                return True

            installers.append({
                'name': filename,
                'label': label,
                'icon': icon,
                'url': settings.STATIC_URL + 'openvpn_installer/' + filename,
                'size': f"{os.path.getsize(file_path) / (1024*1024):.2f} MB"
            })
            return True

        if win_name:
            add_installer(win_name, "Windows (x64)")
        if mac_name:
            add_installer(mac_name, "macOS")
        if linux_name:
            add_installer(linux_name, "Linux")

        # 3. Fallback: also scan the directory to find any other files not explicitly set,
        # but only if not already added via settings
        if installer_dir.exists():
            for f in os.listdir(installer_dir):
                if os.path.isfile(installer_dir / f):
                    # add_installer contains a duplicate check
                    add_installer(f)
                    
        return render(request, 'installer_download.html', {'installers': installers})

class StaffRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_staff

class AdminGenerateOTPView(LoginRequiredMixin, StaffRequiredMixin, View):
    def get(self, request, pk):
        user = get_object_or_404(CustomUser, pk=pk)
        length = int(VPNService.get_vpn_setting('OTP_CODE_LENGTH', '8'))
        
        # Ensure unique code generation
        max_tries = 10
        code = ""
        while max_tries > 0:
            code = ''.join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(length))
            if not OTPCode.objects.filter(code=code).exists():
                break
            max_tries -= 1
            
        OTPCode.objects.create(user=user, code=code)
        
        # Use a very prominent message for the admin
        messages.success(request, f"🚀 OTP THÀNH CÔNG CHO {user.username.upper()}: {code}")
        
        return redirect('admin:vpn_panel_customuser_changelist')

class AdminGenerateOTPAPIView(LoginRequiredMixin, StaffRequiredMixin, View):
    """API endpoint to generate OTP via AJAX for administrative use."""
    def get(self, request, pk):
        user = get_object_or_404(CustomUser, pk=pk)
        length = int(VPNService.get_vpn_setting('OTP_CODE_LENGTH', '8'))
        
        # Ensure unique code generation
        max_tries = 10
        code = ""
        while max_tries > 0:
            code = ''.join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(length))
            if not OTPCode.objects.filter(code=code).exists():
                break
            max_tries -= 1
            
        OTPCode.objects.create(user=user, code=code)
        
        return JsonResponse({
            'success': True,
            'code': code,
            'username': user.username
        })


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
            user = form.save()
            
            from .services import VPNService
            success, result = VPNService.add_client(user.username)
            if success:
                from .models import Client
                client, _ = Client.objects.get_or_create(user=user, defaults={'name': result})
                client.has_ovpn_file = True
                client.save()
                messages.success(request, f"Đã tạo tài khoản {user.username} và tạo tệp OVPN thành công!")
            else:
                messages.warning(request, f"Đã tạo user {user.username} nhưng khởi tạo OVPN thất bại: {result}")
                
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
                firewall_success, msg = VPNService.toggle_lock(user.vpn_client.name, ip, action)
            else:
                firewall_success, msg = False, "Chưa có VPN Client"
            
            status = "MỞ" if user.is_vpn_enabled else "KHÓA"
            if not firewall_success:
                messages.warning(request, f"Đã {status} trên CSDL, nhưng chưa {status} được trên tưởng lửa (Có thể người dùng lấy IP 0.0.0.0): {msg}")
            else:    
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
        
        response = render(request, 'locked.html', {
            'qr_code': get_image_base64(qr_path),
            'group_link': group_link,
            'logo': get_image_base64(logo),
            'site_name': VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
        })
        
        # Explicitly remove/reset COOP/COEP for HTTP Captive Portal environments
        # because browsers reject these headers from untrustworthy origins (HTTP).
        # We manually set them to ensure we override any middleware.
        response["Cross-Origin-Opener-Policy"] = "unsafe-none"
        response["Cross-Origin-Embedder-Policy"] = "unsafe-none"
        # Force removal of the header if still causing issues on some browsers
        if "Cross-Origin-Opener-Policy" in response:
             del response["Cross-Origin-Opener-Policy"]
        if "Cross-Origin-Embedder-Policy" in response:
             del response["Cross-Origin-Embedder-Policy"]
             
        return response

class PortalRedirectView(View):
    """Redirects all captive portal probes to the locked page"""
    def get(self, request):
        response = redirect('locked')
        # Ensure the redirect response also avoids the COOP warning
        if "Cross-Origin-Opener-Policy" in response:
             del response["Cross-Origin-Opener-Policy"]
        return response

class PortalSuccessView(View):
    """Fallback success for probes that don't need redirect"""
    def get(self, request):
        from django.http import HttpResponse
        return HttpResponse("Blocked", content_type="text/plain")

class PasswordResetRequestView(View):
    def get(self, request):
        return render(request, 'password_reset.html')

    def post(self, request):
        user_input = request.POST.get('user_input')
        user = CustomUser.objects.filter(Q(username=user_input) | Q(email=user_input)).first()
        if user and user.email:
            code = ''.join(secrets.choice("0123456789") for _ in range(6))
            from django.utils import timezone
            from datetime import timedelta
            # Use 1 hour expiry for password reset OTP
            expires_at = timezone.now() + timedelta(hours=1)
            OTPCode.objects.create(user=user, code=code, expires_at=expires_at)
            
            subject = _("Mã xác minh đổi mật khẩu")
            site_name = VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
            admin_email = VPNService.get_vpn_setting('ADMIN_EMAIL', settings.DEFAULT_FROM_EMAIL)
            admin_phone = VPNService.get_vpn_setting('ADMIN_PHONE', 'N/A')
            
            message_body = f"Chúng tôi đã nhận được yêu cầu đổi mật khẩu cho tài khoản {user.username}. Mã xác minh của bạn là:\n\n{code}\n\nMã có hiệu lực trong 1 giờ."
            
            html_content = render_to_string('emails/notification_email.html', {
                'subject': subject,
                'user_name': user.full_name or user.username,
                'message_body': message_body,
                'site_name': site_name,
                'support_email': admin_email,
                'support_phone': admin_phone,
            })
            
            try:
                send_mail(
                    subject,
                    f"Mã xác minh của bạn là: {code}",
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    html_message=html_content
                )
                request.session['reset_user_id'] = user.id
                messages.success(request, "Mã xác minh đã được gửi đến email của bạn.")
                return redirect('password_reset_verify')
            except Exception as e:
                logger.error(f"Failed to send password reset email to {user.email}: {e}")
                messages.error(request, f"Lỗi gửi mail: {str(e)}")
        else:
            messages.error(request, "Không tìm thấy tài khoản hoặc tài khoản chưa đăng ký email.")
        return render(request, 'password_reset.html')

class PasswordResetVerifyView(View):
    def get(self, request):
        if 'reset_user_id' not in request.session:
            return redirect('password_reset')
        return render(request, 'password_reset_verify.html')

    def post(self, request):
        user_id = request.session.get('reset_user_id')
        otp_code = request.POST.get('otp')
        password = request.POST.get('password')
        confirm = request.POST.get('confirm_password')

        if not user_id: return redirect('password_reset')
        
        user = CustomUser.objects.get(pk=user_id)
        otp = OTPCode.objects.filter(user=user, code=otp_code, is_used=False, expires_at__gt=timezone.now()).first()
        
        if not otp:
            messages.error(request, "Mã xác minh không hợp lệ hoặc đã hết hạn.")
        elif password != confirm:
            messages.error(request, "Mật khẩu không khớp.")
        else:
            user.set_password(password)
            user.save()
            otp.is_used = True
            otp.save()
            del request.session['reset_user_id']
            messages.success(request, "Đổi mật khẩu thành công! Vui lòng đăng nhập lại.")
            return redirect('login')
            
        return render(request, 'password_reset_verify.html')

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
        import re
        lines = int(request.GET.get('lines', 100))
        service = request.GET.get('service', 'openvpn')
        raw_logs = VPNService.get_service_logs(service=service, lines=lines)
        
        def colorize(line):
            # Service Name indicator (for OpenVPN)
            line = re.sub(r'(openvpn\[\d+\]:)', r'<span class="text-indigo-600 dark:text-indigo-400 font-medium">\1</span>', line)
            
            # Timestamps
            line = re.sub(r'^(\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', r'<span class="text-gray-500">\1</span>', line) # Custom formats
            line = re.sub(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', r'<span class="text-gray-500 dark:text-gray-400">\1</span>', line) # Syslog format
            line = re.sub(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)', r'<span class="text-gray-500">\1</span>', line) # Celery format

            # IP Addresses (v4)
            line = re.sub(r'(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)', r'<span class="text-blue-600 dark:text-blue-400 font-semibold">\1</span>', line)
            
            # Response Codes (HTTP)
            line = re.sub(r'\" (2\d{2}) ', r'\" <span class="text-green-500">\1</span> ', line)
            line = re.sub(r'\" (4\d{2}) ', r'\" <span class="text-orange-500">\1</span> ', line)
            line = re.sub(r'\" (5\d{2}) ', r'\" <span class="text-red-500">\1</span> ', line)

            # Levels
            line = re.sub(r'\b(INFO|SUCCESS|OK|trusted|Initiated|ESTABLISHED|GET|POST)\b', r'<span class="text-green-600 dark:text-green-500 font-bold">\1</span>', line)
            line = re.sub(r'\b(WARNING|restarting|soft|reset|timeout)\b', r'<span class="text-yellow-600 dark:text-yellow-500 font-bold">\1</span>', line)
            line = re.sub(r'\b(error|FAILED|cannot|unsupported|Bad|attack|ERROR|CRITICAL)\b', r'<span class="text-red-600 dark:text-red-500 font-bold">\1</span>', line)
            return line

        formatted_logs = "\n".join([colorize(l) for l in raw_logs.splitlines()])
        return HttpResponse(f"<pre class='font-mono text-xs text-gray-800 dark:text-gray-300 whitespace-pre-wrap leading-relaxed m-0'>{formatted_logs}</pre>")

class AdminTrafficHistoryAPI(LoginRequiredMixin, StaffRequiredMixin, View):
    def get(self, request):
        from django.http import JsonResponse
        history = VPNService.get_traffic_history(limit=30)
        return JsonResponse(history, safe=False)

class AdminTestWebPushView(LoginRequiredMixin, StaffRequiredMixin, View):
    """View to allow admins to trigger a test webpush notification from the console."""
    def post(self, request):
        from webpush import send_user_notification
        import json
        
        # Try JSON first (for fetch requests from console)
        try:
            data = json.loads(request.body)
            head = data.get('head', 'Test Notification 🔔')
            body = data.get('body', 'This is a test notification triggered from backend.')
        except:
             # Fallback to POST parameters
             head = request.POST.get('head', 'Test Notification 🔔')
             body = request.POST.get('body', 'This is a test notification triggered from backend.')

        payload = {
            "head": head,
            "body": body,
            "icon": "/static/images/logo.png"
        }
        
        logger.info(f"Admin {request.user.username} triggered a test webpush to themselves.")
        
        try:
            # Send notification to the current logged-in user
            send_user_notification(user=request.user, payload=payload, ttl=3600)
            return HttpResponse("WebPush sent successfully! check your desktop/phone.", status=200)
        except Exception as e:
            logger.error(f"Failed to send admin test webpush: {str(e)}")
            return HttpResponse(f"Error: {str(e)}", status=500)

class PublicUserListView(View):
    template_name = 'public_user_list.html'
    
    def get(self, request):
        users = CustomUser.objects.exclude(is_superuser=True).order_by('expiry_date')
        
        # Simple search functionality
        search_query = request.GET.get('q', '').strip()
        if search_query:
            users = users.filter(
                Q(username__icontains=search_query) | 
                Q(email__icontains=search_query) |
                Q(full_name__icontains=search_query)
            )
            
        return render(request, self.template_name, {
            'users': users,
            'search_query': search_query,
            'site_name': VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
        })

class PublicUserDetailView(View):
    template_name = 'public_user_detail.html'
    
    def get(self, request, username):
        user = get_object_or_404(CustomUser, username=username)
        if user.is_superuser:
            return HttpResponse("Unauthorized", status=403)
            
        # Get Bank Settings for Dynamic VietQR
        bank_id = Setting.objects.filter(key='BANK_ID').first()
        bank_acc = Setting.objects.filter(key='BANK_ACCOUNT').first()
        bank_name = Setting.objects.filter(key='BANK_ACCOUNT_NAME').first()
        amount = Setting.objects.filter(key='UPGRADE_FEE').first()
        
        # DISABLING DYNAMIC QR TEMPORARILY
        # if bank_id and bank_acc:
        #     # Generate Dynamic VietQR using VietQR.io API
        #     # https://img.vietqr.io/image/<BANK_ID>-<ACCOUNT_NO>-<TEMPLATE>.png?amount=<AMOUNT>&addInfo=<MEMO>&accountName=<NAME>
        #     memo = f"{user.username}"
        #     qr_code = f"https://img.vietqr.io/image/{bank_id.value}-{bank_acc.value}-compact2.png?amount={amount.value if amount else '0'}&addInfo={memo}&accountName={bank_name.value if bank_name else ''}"
        # else:
        #     # Fallback to static QR
        #     qr_setting = Setting.objects.filter(key='PORTAL_QR_CODE').first()
        #     qr_path = qr_setting.value if (qr_setting and qr_setting.value) else VPNService.get_vpn_setting('PORTAL_QR_FALLBACK', "/static/images/qr.png")
        #     qr_code = get_image_base64(qr_path)

        # Always fallback to static QR
        qr_setting = Setting.objects.filter(key='PORTAL_QR_CODE').first()
        qr_path = qr_setting.value if (qr_setting and qr_setting.value) else VPNService.get_vpn_setting('PORTAL_QR_FALLBACK', "/static/images/qr.png")
        qr_code = get_image_base64(qr_path)
        
        return render(request, self.template_name, {
            'user_profile': user,
            'remaining_days': user.remaining_days,
            'qr_code': qr_code,
            'status_text': user.status_text,
            'site_name': VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager')
        })

import json
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

@method_decorator(csrf_exempt, name='dispatch')
class PaymentWebhookView(View):
    """
    Webhook to receive payment confirmations from services like SePay or Casso.
    Example SePay JSON: {"content": "user123", "transferAmount": 50000, ...}
    """
    def post(self, request):
        return HttpResponse("Temporarily disabled", status=200)
        
        # TEMPORARILY DISABLED
        # try:
        #     data = json.loads(request.body)
        #     # Support SePay format as example
        #     content = data.get('content', '') # Transfer memo/content
        #     amount = float(data.get('transferAmount', 0))
        #     
        #     # Find user from memo (case-insensitive)
        #     # We assume memo contains the username
        #     user = CustomUser.objects.filter(username__iexact=content.strip()).first()
        #     
        #     if user:
        #         # Extend user duration
        #         # Logic: Find out how many days to add based on amount (e.g. 50k = 30 days)
        #         # For now, let's just add 30 days if any valid amount is received
        #         days_to_add = int(VPNService.get_vpn_setting('RENEW_DAYS_DEFAULT', '30'))
        #         
        #         # If they are currently expired, move to today
        #         if not user.purchase_date or user.expiry_date < timezone.now().date():
        #             user.purchase_date = timezone.now().date()
        #             user.duration_days = days_to_add
        #         else:
        #             user.duration_days += days_to_add
        #         
        #         user.status = 'ACTIVE'
        #         user.is_vpn_enabled = True
        #         user.save()
        #         
        #         logger.info(f"Payment Webhook: Successfully extended {user.username} for {days_to_add} days. Amount: {amount}")
        #         return HttpResponse("OK", status=200)
        #     else:
        #         logger.warning(f"Payment Webhook: User not found for memo: {content}")
        #         return HttpResponse("User not found", status=404)
        #         
        # except Exception as e:
        #     logger.error(f"Payment Webhook Error: {str(e)}")
        #     return HttpResponse("Error", status=500)
