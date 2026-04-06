from django.shortcuts import redirect
from .models import Client
import logging

logger = logging.getLogger(__name__)

class LockedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        
        # 1. Skip for static files and the locked page itself to avoid infinite loops
        if path.startswith('/static/') or path == '/locked/' or 'favicon' in path:
            return self.get_response(request)

        # 2. Get client IP from request (handling potential proxy/headers)
        ip = request.META.get('REMOTE_ADDR')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()

        if not ip:
            return self.get_response(request)

        # 3. Check if this IP belongs to any client that IS locked in the system
        # Since Client.ip_address might contain comma-separated IPv4,IPv6, we use __contains__
        is_locked_client = Client.objects.filter(ip_address__contains=ip, is_locked=True).exists()

        if is_locked_client:
            # If they are blocked by firewall, we should force them to the locked page 
            # instead of letting Gunicorn/Django redirect them to Login/Dashboard
            return redirect('locked')

        return self.get_response(request)
