from django.shortcuts import render
from .models import Client

class LockedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for static files and the locked page itself to avoid loops
        if request.path.startswith('/static/') or request.path == '/locked/':
            return self.get_response(request)

        # Get client IP from request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Check if this IP belongs to a locked client
        # DEPRECATED: We now show the lock status directly on the dashboard instead of blocking the whole site
        # client = Client.objects.filter(ip_address=ip, is_locked=True).first()
        # if client:
        #     return render(request, 'locked.html')

        return self.get_response(request)
