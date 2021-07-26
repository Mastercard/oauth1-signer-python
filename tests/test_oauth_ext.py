# -*- coding: utf-8 -*-#
#
#
# Copyright (c) 2020-2021 MasterCard International Incorporated
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
import unittest

import hashlib
import re
from importlib import reload
from unittest.mock import MagicMock

from requests import PreparedRequest

import oauth1.authenticationutils as authentication_utils
from oauth1 import coreutils as util
from oauth1.oauth import OAuth
from oauth1.oauth_ext import OAuth1RSA


class OAuthExtTest(unittest.TestCase):
    signing_key = authentication_utils.load_signing_key('./test_key_container.p12', "Password1")
    consumer_key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    data = 'sensistive data'
    mock_prepared_request = PreparedRequest()
    mock_prepared_request.prepare(headers={'Content-type': 'application/json', 'Accept': 'application/json'},
                                  method="POST",
                                  url="http://www.example.com")

    def test_oauth_body_hash_with_body_string(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = "{'A' : 'sensitive data'}"

        oauth_object(OAuthExtTest.mock_prepared_request)
        h = OAuthExtTest.extract_oauth_params(OAuthExtTest.mock_prepared_request)

        self.assertEqual(h['oauth_body_hash'], 'sKrMRMpmhyMJ05fETctDp3UnlDsm1rgOJxQroerFuMs=')

    def test_oauth_body_hash_with_body_bytes(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = b'{"A" : OAuthExtTest.data}'

        oauth_object(OAuthExtTest.mock_prepared_request)
        h = OAuthExtTest.extract_oauth_params(OAuthExtTest.mock_prepared_request)

        hashlib_val = hashlib.sha256(OAuthExtTest.mock_prepared_request.body).digest()
        payload_hash_value = util.base64_encode(hashlib_val)

        self.assertEqual(h['oauth_body_hash'], '9MoCOjWt0ke+o8ZAGij+kZ1goHpfzLIG9ZGty05eIOo=')
        self.assertEqual(h['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_empty(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = ''

        oauth_object(OAuthExtTest.mock_prepared_request)
        h = OAuthExtTest.extract_oauth_params(OAuthExtTest.mock_prepared_request)

        hashlib_val = hashlib.sha256(str(OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.base64_encode(hashlib_val)

        self.assertEqual(h['oauth_body_hash'], payload_hash_value)
        self.assertEqual(h['oauth_body_hash'], '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')

    def test_oauth_body_hash_with_body_none(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = None

        oauth_object(OAuthExtTest.mock_prepared_request)
        h = OAuthExtTest.extract_oauth_params(OAuthExtTest.mock_prepared_request)

        hashlib_val = hashlib.sha256(str("").encode('utf8')).digest()
        payload_hash_value = util.base64_encode(hashlib_val)

        self.assertEqual(h['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_empty_or_none(self):
        def prep_request():
            req = PreparedRequest()
            req.prepare(headers={'Content-type': 'application/json', 'Accept': 'application/json'},
                        method="POST",
                        url="http://www.example.com")
            return req

        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        request_empty = prep_request()
        request_none = prep_request()

        request_empty.body = ""
        request_none.body = None

        oauth_object(request_empty)
        request_empty_header = OAuthExtTest.extract_oauth_params(request_empty)

        oauth_object(request_none)
        request_none_header = OAuthExtTest.extract_oauth_params(request_none)

        empty_string_hash = hashlib.sha256(str("").encode('utf8')).digest()
        empty_string_encoded = util.base64_encode(empty_string_hash)

        self.assertEqual(request_empty_header['oauth_body_hash'], empty_string_encoded)
        self.assertEqual(request_empty_header['oauth_body_hash'], '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
        self.assertEqual(request_none_header['oauth_body_hash'], empty_string_encoded)
        self.assertEqual(request_none_header['oauth_body_hash'], '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')

    def test_oauth_body_hash_with_body_multipart(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        mock_request = PreparedRequest()
        mock_request.prepare(headers={'Content-type': 'multipart/form-data'},
                             method="GET",
                             url="http://www.mastercard.com")

        oauth_object(mock_request)
        h = OAuthExtTest.extract_oauth_params(mock_request)

        hashlib_val = hashlib.sha256(str(OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.base64_encode(hashlib_val)

        self.assertEqual(h['oauth_body_hash'], payload_hash_value)
        self.assertEqual(h['oauth_body_hash'], '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')

    def test_call(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        call_object = oauth_object.__call__(OAuthExtTest.mock_prepared_request)
        self.assertTrue("Authorization" in call_object.headers)

    def test_ext_oauth_header_equals_to_non_ext_generated(self):
        util.get_nonce = MagicMock(return_value=util.get_nonce())
        util.get_timestamp = MagicMock(return_value=util.get_timestamp())

        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        call_object = oauth_object(OAuthExtTest.mock_prepared_request)

        header = OAuth.get_authorization_header(OAuthExtTest.mock_prepared_request.url,
                                                OAuthExtTest.mock_prepared_request.method,
                                                OAuthExtTest.mock_prepared_request.body,
                                                OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        reload(util)
        self.assertTrue("Authorization" in call_object.headers)
        self.assertEqual(header, call_object.headers['Authorization'])

    def test_with_none_arguments(self):
        oauth_object = OAuth1RSA(None, None)
        request = PreparedRequest()
        call_object = oauth_object(request)
        self.assertIsNone(call_object.headers)

    @staticmethod
    def to_pair(obj):
        split_index = obj.index('=')
        key = obj[:split_index]
        value = obj[split_index + 2:]
        return key, value[:-1]

    @staticmethod
    def extract_oauth_params(prepared_request: PreparedRequest):
        oauth_header = prepared_request.headers['Authorization']
        h = str(re.sub(r'^OAuth ', '', oauth_header))
        res = dict([OAuthExtTest.to_pair(item) for item in h.split(',')])
        return res


if __name__ == '__main__':
    unittest.main()
