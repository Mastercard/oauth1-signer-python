# -*- coding: utf-8 -*-#
#
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
import unittest

import requests
from unittest.mock import patch

from oauth1.oauth import SignatureMethod
from oauth1.signer_interceptor import SignerInterceptor
from oauth1.signer_interceptor import add_signer_layer
from oauth1.signer_interceptor import get_signer_layer

from tests.oauth_assertions import assert_oauth_header_is_valid, expected_body_hash


class OAuthInterceptorTest(unittest.TestCase):
    """ add an interceptor, check api client has changed """

    def test_add_interceptor(self):
        key_file = './test_key_container.p12'
        key_password = "Password1"
        consumer_key = 'dummy'

        signer_request = MockApiRestClient(requests)

        signing_layer1 = get_signer_layer(signer_request)
        add_signer_layer(signer_request, key_file, key_password, consumer_key)
        signing_layer2 = get_signer_layer(signer_request)
        self.assertNotEqual(signing_layer1, signing_layer2)

    def test_oauth_signing_pss_adds_valid_authorization_header(self):
        key_file = './test_key_container.p12'
        key_password = 'Password1'
        consumer_key = 'dummy'
        nonce = 'fixednonce123456'
        timestamp = 1700000000
        captured_headers = {}

        def request(method, uri, **kwargs):
            captured_headers.update(kwargs['headers'])
            return kwargs

        signer = SignerInterceptor(key_file, key_password, consumer_key,
                                   signature_method=SignatureMethod.RSA_PSS_SHA256)
        signed_request = signer.oauth_signing(request)

        with patch('oauth1.coreutils.get_nonce', return_value=nonce), \
                patch('oauth1.coreutils.get_timestamp', return_value=timestamp):
            signed_request('POST', 'https://www.example.com/resource', body='payload',
                           query_params={'alpha': '1'}, headers={})

        assert_oauth_header_is_valid(
            self,
            uri='https://www.example.com/resource?alpha=1',
            method='POST',
            payload='payload',
            header=captured_headers['Authorization'],
            public_key=signer.signing_key.public_key(),
            expected_consumer_key=consumer_key,
            expected_nonce=nonce,
            expected_timestamp=timestamp,
            expected_signature_method='RSA-PSS',
            signature_method=SignatureMethod.RSA_PSS_SHA256,
        )

    def test_oauth_signing_invalid_signature_method_raises_value_error(self):
        def request(method, uri, **kwargs):
            return kwargs

        signer = SignerInterceptor('./test_key_container.p12', 'Password1', 'dummy',
                                   signature_method='invalid')
        signed_request = signer.oauth_signing(request)

        with self.assertRaisesRegex(
                ValueError,
                r"Invalid signature_method argument\."):
            signed_request('POST', 'https://www.example.com/resource', body='payload', headers={})

    def test_oauth_signing_default_rsa_sha256_adds_valid_authorization_header(self):
        key_file = './test_key_container.p12'
        key_password = 'Password1'
        consumer_key = 'dummy'
        nonce = 'fixednonce123456'
        timestamp = 1700000000
        captured_headers = {}

        def request(method, uri, **kwargs):
            captured_headers.update(kwargs['headers'])
            return kwargs

        signer = SignerInterceptor(key_file, key_password, consumer_key)
        signed_request = signer.oauth_signing(request)

        with patch('oauth1.coreutils.get_nonce', return_value=nonce), \
                patch('oauth1.coreutils.get_timestamp', return_value=timestamp):
            signed_request('POST', 'https://www.example.com/resource', body='payload',
                           query_params={'alpha': '1'}, headers={})

        assert_oauth_header_is_valid(
            self,
            uri='https://www.example.com/resource?alpha=1',
            method='POST',
            payload='payload',
            header=captured_headers['Authorization'],
            public_key=signer.signing_key.public_key(),
            expected_consumer_key=consumer_key,
            expected_nonce=nonce,
            expected_timestamp=timestamp,
            expected_signature_method='RSA-SHA256',
            signature_method=SignatureMethod.RSA_SHA256,
        )

    # The cryptographic test above checks that interceptor-driven RSA-PSS signing is
    # valid. This snapshot test stubs the signature value so serialization details of
    # the Authorization header can be asserted exactly and repeatably.
    def test_oauth_signing_pss_snapshot_header(self):
        captured_headers = {}
        body_hash = expected_body_hash('payload')

        def request(method, uri, **kwargs):
            captured_headers.update(kwargs['headers'])
            return kwargs

        signer = SignerInterceptor('./test_key_container.p12', 'Password1', 'dummy',
                                   signature_method=SignatureMethod.RSA_PSS_SHA256)
        signed_request = signer.oauth_signing(request)

        with patch('oauth1.coreutils.get_nonce', return_value='fixednonce123456'), \
                patch('oauth1.coreutils.get_timestamp', return_value=1700000000), \
                patch('oauth1.oauth.OAuth.sign_message', return_value='fixed+/sig='):
            signed_request('POST', 'https://www.example.com/resource', body='payload', headers={})

        self.assertEqual(
            'OAuth oauth_consumer_key="dummy",oauth_nonce="fixednonce123456",'
            'oauth_timestamp="1700000000",oauth_signature_method="RSA-PSS",oauth_version="1.0",'
            f'oauth_body_hash="{body_hash}",'
            'oauth_signature="fixed%2B%2Fsig%3D"',
            captured_headers['Authorization'],
        )

    def test_oauth_signing_default_rsa_sha256_snapshot_header(self):
        captured_headers = {}
        body_hash = expected_body_hash('payload')

        def request(method, uri, **kwargs):
            captured_headers.update(kwargs['headers'])
            return kwargs

        signer = SignerInterceptor('./test_key_container.p12', 'Password1', 'dummy')
        signed_request = signer.oauth_signing(request)

        with patch('oauth1.coreutils.get_nonce', return_value='fixednonce123456'), \
                patch('oauth1.coreutils.get_timestamp', return_value=1700000000), \
                patch('oauth1.oauth.OAuth.sign_message', return_value='fixed+/sig='):
            signed_request('POST', 'https://www.example.com/resource', body='payload', headers={})

        self.assertEqual(
            'OAuth oauth_consumer_key="dummy",oauth_nonce="fixednonce123456",'
            'oauth_timestamp="1700000000",oauth_signature_method="RSA-SHA256",oauth_version="1.0",'
            f'oauth_body_hash="{body_hash}",'
            'oauth_signature="fixed%2B%2Fsig%3D"',
            captured_headers['Authorization'],
        )


class MockApiRestClient(object):
    def __init__(self, request):
        self.request = request
        self.rest_client = request


if __name__ == '__main__':
    unittest.main()

def __del__(self):
        self.child.terminate()
        self.child.communicate()
