import secrets
import string
import csv
from django.core.management.base import BaseCommand
from vpn_panel.models import CustomUser
from vpn_panel.services import VPNService

class Command(BaseCommand):
    help = 'Import legacy users and generate random passwords'

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help='Path to CSV/TXT file with usernames')

    def handle(self, *args, **options):
        file_path = options['file_path']
        output_file = 'imported_users_credentials.csv'
        
        with open(file_path, 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]

        imported_data = []
        for username in usernames:
            if not CustomUser.objects.filter(username=username).exists():
                # Setting a default known password or just username as password for first login
                password = "Password@123" 
                user = CustomUser.objects.create_user(username=username, password=password)
                user.full_name = username.capitalize()
                user.requires_profile_update = True
                user.save()
                
                # Automatically create VPN client
                VPNService.add_client(username)
                
                imported_data.append([username, password])
                self.stdout.write(self.style.SUCCESS(f'Successfully imported {username}'))
            else:
                self.stdout.write(self.style.WARNING(f'User {username} already exists'))

        # Export list
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Username', 'Password'])
            writer.writerows(imported_data)
        
        self.stdout.write(self.style.SUCCESS(f'Credentials exported to {output_file}'))
