from django.urls import path
from . import views

urlpatterns = [
    path("api/login/", views.login),
    path("api/me/", views.me),
    path("__debug__/toolbar/", views.debug),
]
