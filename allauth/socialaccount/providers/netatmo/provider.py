from allauth.account.models import EmailAddress
from allauth.socialaccount.app_settings import QUERY_EMAIL
from allauth.socialaccount.providers.base import AuthAction, ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider

class NetAtMoAccount(ProviderAccount):
    def to_str(self):
        dflt = super().to_str()
        return self.account.extra_data.get('name', dflt)


class NetAtMoProvider(OAuth2Provider):
    id = 'netatmo'
    name = 'Netatmo'
    account_class = NetAtMoAccount

    def get_default_scope(self):
        scope = ['read_station']
        return scope

        return ret

    def extract_uid(self, data):
        return str(data['id'])

    def extract_common_fields(self, data):
        return dict(email=data.get('mail'),
                    username=data.get('username'),
                    last_name=data.get('name'),
                    first_name=data.get('name'))

    def extract_email_addresses(self, data):
        ret = []
        email = data.get('email')
        if email and data.get('verified_email'):
            ret.append(EmailAddress(email=email,
                       verified=True,
                       primary=True))
        return ret


provider_classes = [NetAtMoProvider]
