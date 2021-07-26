# -*- coding: utf-8 -*-
#
# Copyright 2020-2021 Mastercard
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of
# conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
# Neither the name of the MasterCard International Incorporated nor the names of its
# contributors may be used to endorse or promote products derived from this software
# without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
from OpenSSL.crypto import PKey
from requests import PreparedRequest
from requests.auth import AuthBase

from .oauth import OAuth


class OAuth1RSA(AuthBase):
    """OAuth1 RSA-SHA256 requests's auth helper
    Usage:
        >>> from oauth1 import authenticationutils
        >>> from oauth1.oauth_ext import OAuth1RSA
        >>> import requests
        >>> CONSUMER_KEY = 'secret-consumer-key'
        >>> pk = authenticationutils.load_signing_key('instance/masterpass.pfx', 'a3fa02536a')
        >>> oauth = OAuth1RSA(CONSUMER_KEY, pk)
        >>> requests.post('https://endpoint.com/the/route', data={'foo': 'bar'}, auth=oauth)
    """

    def __init__(self, consumer_key: str, signing_key: PKey):
        self.consumer_key = consumer_key
        self.signing_key = signing_key

    def __call__(self, r: PreparedRequest):
        method = r.method.upper() if r.method is not None else r.method
        if all(v is not None for v in [r, self.consumer_key, self.signing_key]):
            r.headers['Authorization'] = \
                OAuth.get_authorization_header(uri=r.url,
                                               method=method,
                                               payload=r.body,
                                               consumer_key=self.consumer_key,
                                               signing_key=self.signing_key)
        return r
