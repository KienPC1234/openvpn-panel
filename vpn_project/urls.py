from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView, RedirectView
from vpn_panel import views

urlpatterns = [
    path('favicon.ico', RedirectView.as_view(url='/static/favicon/favicon.ico', permanent=True)),
    path('site.webmanifest', RedirectView.as_view(url='/static/favicon/site.webmanifest', permanent=True)),
    path('sw.js', TemplateView.as_view(template_name="sw.js", content_type='application/javascript'), name='sw_js'),
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('i18n/', include('django.conf.urls.i18n')),
    path('', include('vpn_panel.urls')),
    path('webpush/', include('webpush.urls')),
    path('admin/vpn_panel/logs/', views.AdminServiceLogView.as_view(), name='admin_vpn_logs'),
    path('admin/vpn_panel/logs/content/', views.AdminServiceLogContent.as_view(), name='admin_vpn_logs_content'),
    path('admin/', admin.site.urls),
]
