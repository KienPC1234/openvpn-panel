from .services import VPNService
from django.conf import settings

def vpn_settings(request):
    return {
        'site_name': VPNService.get_vpn_setting('SITE_NAME', 'OpenVPN Manager'),
        'footer_text': VPNService.get_vpn_setting('FOOTER_TEXT', 'Premium VPN Management. All rights reserved.'),
        'currency_symbol': VPNService.get_vpn_setting('CURRENCY_SYMBOL', 'VNĐ'),
        'site_logo': VPNService.get_vpn_setting('SITE_LOGO', getattr(settings, 'SITE_LOGO', '/static/images/logo.png')),
        'WEBPUSH_PUBLIC_KEY': getattr(settings, 'WEBPUSH_SETTINGS', {}).get('VAPID_PUBLIC_KEY', ''),
        'support_text': VPNService.get_vpn_setting('SUPPORT_BUTTON_TEXT', 'Telegram Support'),
        'support_link': VPNService.get_vpn_setting('SUPPORT_LINK', 'https://t.me/your_group'),
    }
