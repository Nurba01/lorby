from django.contrib import admin
from django.urls import path, include, re_path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

schema_view = get_schema_view(
   openapi.Info(
      title="Lorby API",
      default_version='v1',
       description="API Lorby предоставляет доступ к различным запросам, требующим аутентификации "
                   "с помощью токена Bearer. "
                   "Для аутентификации включите 'Bearer {access_token}' в заголовок 'Authorization'.",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    re_path(r'^lorby/swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^lorby/swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^lorby/redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('lorby/admin/', admin.site.urls),
    path('lorby/authentication/', include("authentication.urls")),
]

