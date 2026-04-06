from .services import VPNService
from django.conf import settings
from .views import get_image_base64

def vpn_settings(request):
    site_logo = VPNService.get_vpn_setting('SITE_LOGO', getattr(settings, 'SITE_LOGO', '/static/images/logo.png'))
    footer_links_raw = VPNService.get_vpn_setting('FOOTER_LINKS', '') # Format: Label|URL,Label|URL
    footer_links = []
    if footer_links_raw:
        for item in footer_links_raw.split(','):
            if '|' in item:
                label, url = item.split('|', 1)
                footer_links.append({'label': label.strip(), 'url': url.strip()})

    return {
        'site_name': VPNService.get_vpn_setting('SITE_NAME', 'VPN Panel'),
        'footer_text': VPNService.get_vpn_setting('FOOTER_TEXT', 'Premium VPN Management.'),
        'currency_symbol': VPNService.get_vpn_setting('CURRENCY_SYMBOL', 'VNĐ'),
        'site_logo': site_logo,
        'site_logo_base64': get_image_base64(site_logo),
        'WEBPUSH_PUBLIC_KEY': getattr(settings, 'WEBPUSH_SETTINGS', {}).get('VAPID_PUBLIC_KEY', ''),
        'support_text': VPNService.get_vpn_setting('SUPPORT_BUTTON_TEXT', 'Zalo Support'),
        'support_link': VPNService.get_vpn_setting('SUPPORT_LINK', '#'),
        'mess_link': VPNService.get_vpn_setting('MESS_LINK', '#'),
        'grace_days': int(VPNService.get_vpn_setting('GRACE_PERIOD_DAYS', '0')),
        'unlock_free_days': int(VPNService.get_vpn_setting('UNLOCK_FREE_DAYS', '1')),
        'recaptcha_site_key': getattr(settings, 'RECAPTCHA_SITE_KEY', ''),
        'footer_links': footer_links,
    }
