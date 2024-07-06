from django.urls import path
from authentication.views import (
    UserRegisterView,
    LoginView,
    ConfirmCodeView,
    ResendConfirmationCodeView,
    TokenRefreshView,
    LogoutView,
)


urlpatterns = [
    path('login/', LoginView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegisterView.as_view(), name='user-registration'),
    path('resend-confirmation-code/', ResendConfirmationCodeView.as_view(), name='resend-confirmation'),
    path('email-confirm/', ConfirmCodeView.as_view(), name='email-confirm'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
