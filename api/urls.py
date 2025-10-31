from django.urls import path, include
from . import views


urlpatterns = [
    path('google/', views.Google_login.as_view(), name='google_auth'),
    path('google/callback/', views.Google_callback.as_view(), name='google_auth_callback'),

    path('m_login/', views.Manual_login.as_view(), name='manual_login'),
    path('change-password/', views.ChangePassword.as_view(), name='change_password'),

    path('token-exchange/', views.TokenExchange.as_view(), name='token_exchange'),
    path('refresh-access/', views.RefreshAccessToken.as_view(), name='refresh_access'),

    path('public-key/', views.PublicKeyView.as_view(), name='public_key'),


]