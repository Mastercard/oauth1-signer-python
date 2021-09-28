# -*- coding: utf-8 -*-
#
# Copyright 2019-2021 Mastercard
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

            auth_header = OAuth.get_authorization_header(uri, args[0], in_body, self.consumer_key, self.signing_key)

            in_headers = kwargs.get("headers", None)
            if not in_headers:
                in_headers = dict()
                kwargs["headers"] = in_headers

            in_headers["Authorization"] = auth_header

            res = func(*args, **kwargs)

            return res

        request_function.__oauth__ = True
        return request_function


@deprecated(version='1.1.3', reason="Use add_signer_layer(api_client, key_file, key_password, consumer_key) instead")
def add_signing_layer(self, api_client, key_file, key_password, consumer_key):
    add_signer_layer(api_client, key_file, key_password, consumer_key)


def add_signer_layer(api_client, key_file, key_password, consumer_key):
    """Create and load configuration. Decorate APIClient.request with header signing"""

    api_signer = SignerInterceptor(key_file, key_password, consumer_key)

    api_client.rest_client.request = api_signer.oauth_signing(api_client.rest_client.request)


@deprecated(version='1.1.3', reason="Use get_signer_layer(api_client) instead")
def get_signing_layer(self, api_client):
    return get_signer_layer(api_client)


def get_signer_layer(api_client):
    return api_client.rest_client.request
