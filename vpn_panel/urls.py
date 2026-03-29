from django.urls import path
from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('register/verify/', views.VerifyRegisterOTPView.as_view(), name='verify_register_otp'),
    path('profile-update/', views.ProfileUpdateView.as_view(), name='profile_update'),
    path('download/otp/', views.OTPDownloadView.as_view(), name='otp_download'),
    path('download/installer/', views.InstallerView.as_view(), name='installer_download'),
    path('admin/generate-otp/<int:pk>/', views.AdminGenerateOTPView.as_view(), name='admin_generate_user_otp'),
    path('locked/', views.LockedView.as_view(), name='locked'),
    
    # Captive Portal Detection Endpoints
    path('generate_204', views.PortalRedirectView.as_view()),
    path('hotspot-detect.html', views.PortalRedirectView.as_view()),
    path('connecttest.txt', views.PortalSuccessView.as_view()),
    path('ncsi.txt', views.PortalSuccessView.as_view()),
    path('success.txt', views.PortalSuccessView.as_view()),
    
    path('partials/clients/', views.ClientsPartialView.as_view(), name='clients_partial'),
    path('partials/stats/', views.StatsPartialView.as_view(), name='stats_partial'),
    path('api/client/add/', views.AddClientView.as_view(), name='add_client'),
    path('api/client/delete/<int:pk>/', views.DeleteClientView.as_view(), name='delete_client'),
    path('api/client/toggle/<int:pk>/', views.ToggleLockView.as_view(), name='toggle_lock'),
    path('api/client/download/<int:pk>/', views.DownloadOvpnView.as_view(), name='download_ovpn'),
    path('api/service/restart/', views.RestartServiceView.as_view(), name='restart_service'),
    path('api/admin/webpush-test/', views.AdminTestWebPushView.as_view(), name='admin_webpush_test'),
    path('admin/api/traffic/', views.AdminTrafficHistoryAPI.as_view(), name='admin_traffic_api'),
    
    # Admin User Management
    path('admin/users/', views.AdminUserManageView.as_view(), name='admin_user_manage'),
    path('admin/users/delete/<int:pk>/', views.AdminUserDeleteView.as_view(), name='admin_user_delete'),
    path('admin/users/toggle/<int:pk>/', views.AdminUserToggleLockView.as_view(), name='admin_user_toggle_lock'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password_reset_verify'),
]
