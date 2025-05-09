from django.urls import path
from .views import RegisterView, ProfileView, LoginView, LogoutView, PasswordChangeView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),   # Login qilish uchun view. Ushbu view DRF simpleJWT ning default yozilgan LOgin uchun view
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),   # Mavjud tokenni refresh qiladi. Ya'ni access tokenni yangilaydi
    path('profile', ProfileView.as_view(), name='profile'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('password-change', PasswordChangeView.as_view(), name='password-change'),
]


