from functools import wraps
from oauth1.oauth import OAuth
from oauth1 import authenticationutils
from urllib.parse import urlencode
from deprecated import deprecated


class SignerInterceptor(object):

    def __init__(self, key_file, key_password, consumer_key):
        """Load signing key."""
        self.signing_key = authenticationutils.load_signing_key(key_file, key_password)
        self.consumer_key = consumer_key

    def oauth_signing(self, func):
        """Decorator for API request. func is APIClient.request"""

        @wraps(func)
        def request_function(*args, **kwargs):  # pragma: no cover
            in_body = kwargs.get("body", None)
            query_params = kwargs.get("query_params", None)

            uri = args[1]
            if query_params:
                uri += '?' + urlencode(query_params)

            auth_header = OAuth().get_authorization_header(uri, args[0], in_body,
                                                           self.consumer_key, self.signing_key)

            in_headers = kwargs.get("headers", None)
            if not in_headers:
                in_headers = dict()
                kwargs["headers"] = in_headers

            in_headers["Authorization"] = auth_header

            return func(*args, **kwargs)

        request_function.__oauth__ = True
        return request_function


@deprecated(version='1.1.3', reason="Use add_signer_layer(api_client, key_file, key_password, consumer_key) instead")
def add_signing_layer(self, api_client, key_file, key_password, consumer_key):
    add_signer_layer(api_client, key_file, key_password, consumer_key)


def add_signer_layer(api_client, key_file, key_password, consumer_key):
    """Create and load configuration. Decorate APIClient.request with header signing"""

    api_signer = SignerInterceptor(key_file, key_password, consumer_key)
    api_client.request = api_signer.oauth_signing(api_client.request)


@deprecated(version='1.1.3', reason="Use get_signer_layer(api_client) instead")
def get_signing_layer(self, api_client):
    return get_signer_layer(api_client)


def get_signer_layer(api_client):
    return api_client.request
