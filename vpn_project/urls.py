from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView
from vpn_panel import views

urlpatterns = [
    path('sw.js', TemplateView.as_view(template_name="sw.js", content_type='application/javascript'), name='sw_js'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('', include('vpn_panel.urls')),
    path('webpush/', include('webpush.urls')),
    path("__reload__/", include("django_browser_reload.urls")),
    path('admin/vpn_panel/logs/', views.AdminServiceLogView.as_view(), name='admin_vpn_logs'),
    path('admin/vpn_panel/logs/content/', views.AdminServiceLogContent.as_view(), name='admin_vpn_logs_content'),
    path('admin/', admin.site.urls),
]
