from django.core.management.base import BaseCommand
from vpn_panel.models import Setting

class Command(BaseCommand):
    help = 'Initialize bank and payment settings for dynamic QR and Webhooks'

    def handle(self, *args, **options):
        settings_to_create = [
            {
                'key': 'BANK_ID',
                'value': 'VCB',
                'description': 'Mã ngân hàng (ví dụ: VCB, MB, ICB... tham khảo VietQR.io)'
            },
            {
                'key': 'BANK_ACCOUNT',
                'value': '0000000000',
                'description': 'Số tài khoản ngân hàng nhận tiền'
            },
            {
                'key': 'BANK_ACCOUNT_NAME',
                'value': 'NGUYEN VAN A',
                'description': 'Tên chủ tài khoản (hiển thị trên QR)'
            },
            {
                'key': 'UPGRADE_FEE',
                'value': '50000',
                'description': 'Số tiền mặc định khi quét mã (VNĐ)'
            },
            {
                'key': 'RENEW_DAYS_DEFAULT',
                'value': '30',
                'description': 'Số ngày được cộng thêm sau khi thanh toán thành công'
            },
        ]

        for s in settings_to_create:
            obj, created = Setting.objects.get_or_create(
                key=s['key'],
                defaults={'value': s['value'], 'description': s['description']}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created setting: {s['key']}"))
            else:
                self.stdout.write(self.style.WARNING(f"Setting already exists: {s['key']}"))
