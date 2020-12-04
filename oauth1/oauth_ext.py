import time
from uuid import uuid4

from requests.auth import AuthBase
from OpenSSL.crypto import PKey
from OpenSSL import crypto
from requests import PreparedRequest
import hashlib
from . import coreutils as util

HASH_SHA256 = 'SHA256'


def hash_func(hash_alg):
    return {
        HASH_SHA256: hashlib.sha256
    }[hash_alg]


class OAuth1RSA(AuthBase):
    """OAuth1 RSA-SHA256 requests's auth helper
    Usage:
        >>> from oauth1 import authenticationutils
        >>> from oauth1.auth_ext import OAuth1RSA
        >>> import requests
        >>> CONSUMER_KEY = 'secret-consumer-key'
        >>> pk = authenticationutils.load_signing_key('instance/masterpass.pfx', 'a3fa02536a')
        >>> oauth = OAuth1RSA(CONSUMER_KEY, pk)
        >>> requests.post('https://endpoint.com/the/route', data={'foo': 'bar'}, auth=oauth)
    """

    def __init__(self, consumer_key: str, signing_key: PKey, hash_alg=HASH_SHA256):
        self.consumer_key = consumer_key
        self.signing_key = signing_key
        self.hash_alg = hash_alg
        self.hash_f = hash_func(hash_alg)

    def __call__(self, r: PreparedRequest):
        payload = {
            'oauth_version': '1.0',
            'oauth_nonce': self.nonce(),
            'oauth_timestamp': str(self.timestamp()),
            'oauth_signature_method': f'RSA-{self.hash_alg}',
            'oauth_consumer_key': self.consumer_key
        }

        # Google's body hash extension
        payload = self.oauth_body_hash(r, payload)

        signable_message = self.signable_message(r, payload)
        signature = self.signature(signable_message)
        payload['oauth_signature'] = signature

        h = self._generate_header(payload)

        r.headers['Authorization'] = h
        return r

    @staticmethod
    def nonce():
        return str(uuid4())

    @staticmethod
    def timestamp():
        return int(time.time())

    def _hash(self, message: str) -> str:
        if type(message) is str:
            return self.hash_f(message.encode('utf8')).digest()
        elif type(message) is bytes:
            return self.hash_f(message).digest()
        else:
            # Generally for calls where the payload is empty. Eg: get calls
            # Fix for AttributeError: 'NoneType' object has no attribute 'encode'
            return self.hash_f(str(message).encode('utf8')).digest()

    @staticmethod
    def signable_message(r: PreparedRequest, payload: dict):
        params = [
            r.method.upper(),
            util.normalize_url(r.url),
            util.normalize_params(r.url, payload)
        ]
        params = map(util.uri_rfc3986_encode, params)
        return '&'.join(params)

    def signature(self, message: str):
        signature = crypto.sign(self.signing_key, message, self.hash_alg)
        return util.base64_encode(signature)

    @staticmethod
    def _generate_header(payload: dict):
        _ = util.uri_rfc3986_encode
        pts = [f'{_(k)}="{_(v)}"' for k, v in sorted(payload.items())]
        msg = ','.join(pts)
        return f'OAuth {msg}'

    def oauth_body_hash(self, r: PreparedRequest, payload: dict):
        if r.headers and r.headers.get('content-type') == 'multipart/form-data':
            return payload

        body = r.body
        payload['oauth_body_hash'] = util.uri_rfc3986_encode(util.base64_encode(self._hash(body)))
        return payload