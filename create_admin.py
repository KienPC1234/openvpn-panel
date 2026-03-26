import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_project.settings')
django.setup()

from vpn_panel.models import CustomUser

if not CustomUser.objects.filter(username='admin').exists():
    CustomUser.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print("Superuser 'admin' created with password 'admin123'")
else:
    print("Superuser 'admin' already exists")
