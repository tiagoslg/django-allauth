from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns

from .provider import NetAtMoProvider


urlpatterns = default_urlpatterns(NetAtMoProvider)
