from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static

auth_urls = [
    path('google/', views.Google_login.as_view(), name='google_auth'),
    path('google/callback/', views.Google_callback.as_view(), name='google_auth_callback'),

    path('token-exchange/', views.TokenExchange.as_view(), name='token_exchange'),
    path('refresh-access/', views.RefreshAccessToken.as_view(), name='refresh_access'),

    path('public-key/', views.PublicKeyView.as_view(), name='public_key'),

    # Auth features
    # path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # path('profile/change-photo/', views.ChangeProfilePhotoView.as_view(), name='change_photo'),
    # path('profile/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
]


urlpatterns = [
    # path('', views.home, name='home'),
     path('auth/', include((auth_urls, "auth"), namespace="auth")),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)