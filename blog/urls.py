from django.urls import path
from . import views

urlpatterns = [
    path('api/register/', views.register),
    path('api/login/', views.user_login),
    path('api/create-post/', views.create_post),
    path('api/posts/', views.list_posts),
    path('api/post/<int:id>/', views.post_detail),
    path('api/post/<int:id>/comment/', views.add_comment),
]
