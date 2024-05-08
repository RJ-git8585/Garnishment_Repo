from django.urls import path
from . import views
from .views import EmployerProfile

urlpatterns = [
    path("register", views.register, name="register"),
    path("login",views.login, name="login"),
    path('dashboard',views.dashboard,name='dashboard'),
    path('logout',views.logout,name='logout'),
    path('update<str:pk>', views.update, name="update"),
    path('employer-profile/', EmployerProfile, name='employer_profile'),
]