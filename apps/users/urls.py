from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('verify-otp/', VerifyOTPView.as_view()),
    path('login/', LoginView.as_view()),
    path('password-reset/', PasswordResetRequestView.as_view()),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view()),
    path('change-password/', ChangePasswordView.as_view()),
]
