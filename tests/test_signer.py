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
from unittest.mock import patch

import requests
from requests import Request, Session
from requests.auth import AuthBase

import oauth1.authenticationutils as authenticationutils
from oauth1.oauth import SignatureMethod
from oauth1.signer import OAuthSigner
from tests.oauth_assertions import assert_oauth_header_is_valid, expected_body_hash


class SignerTest(unittest.TestCase):
    signing_key = authenticationutils.load_signing_key('./test_key_container.p12', "Password1")
    consumer_key = 'dummy'
    uri = "https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0"

    def test_sign_request(self):
        request = Request()
        request.method = "POST"
        request.data = ""

        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key)
        request = signer.sign_request(SignerTest.uri, request)
        auth_header = request.headers['Authorization']
        self.assertTrue("OAuth" in auth_header)
        self.assertTrue("dummy" in auth_header)

    def test_sign_request_pss(self):
        request = Request()
        request.method = 'POST'
        request.data = 'payload'
        request.headers = {}
        nonce = 'fixednonce123456'
        timestamp = 1700000000

        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key,
                             signature_method=SignatureMethod.RSA_PSS_SHA256)

        with patch('oauth1.coreutils.get_nonce', return_value=nonce), \
                patch('oauth1.coreutils.get_timestamp', return_value=timestamp):
            request = signer.sign_request(SignerTest.uri, request)

        assert_oauth_header_is_valid(
            self,
            uri=SignerTest.uri,
            method=request.method,
            payload=request.data,
            header=request.headers['Authorization'],
            public_key=SignerTest.signing_key.public_key(),
            expected_consumer_key=SignerTest.consumer_key,
            expected_nonce=nonce,
            expected_timestamp=timestamp,
            expected_signature_method='RSA-PSS',
            signature_method=SignatureMethod.RSA_PSS_SHA256,
        )

    def test_sign_request_with_default_signature_method(self):
        request = Request()
        request.method = 'POST'
        request.data = 'payload'
        request.headers = {}
        nonce = 'fixednonce123456'
        timestamp = 1700000000

        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key)

        with patch('oauth1.coreutils.get_nonce', return_value=nonce), \
                patch('oauth1.coreutils.get_timestamp', return_value=timestamp):
            request = signer.sign_request(SignerTest.uri, request)

        assert_oauth_header_is_valid(
            self,
            uri=SignerTest.uri,
            method=request.method,
            payload=request.data,
            header=request.headers['Authorization'],
            public_key=SignerTest.signing_key.public_key(),
            expected_consumer_key=SignerTest.consumer_key,
            expected_nonce=nonce,
            expected_timestamp=timestamp,
            expected_signature_method='RSA-SHA256',
            signature_method=SignatureMethod.RSA_SHA256,
        )

    def test_sign_request_invalid_signature_method_raises_value_error(self):
        request = Request()
        request.method = 'POST'
        request.data = 'payload'
        request.headers = {}
        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key,
                             signature_method='invalid')

        with self.assertRaisesRegex(
                ValueError,
                r"Invalid signature_method argument\."):
            signer.sign_request(SignerTest.uri, request)

    # The real-signature test above verifies the RSA-PSS branch cryptographically.
    # This one fixes the signature output so the final Authorization header string
    # can be asserted exactly without PSS salt randomness changing the result.
    def test_sign_request_pss_snapshot_header(self):
        request = Request()
        request.method = 'POST'
        request.data = 'payload'
        request.headers = {}
        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key,
                             signature_method=SignatureMethod.RSA_PSS_SHA256)

        body_hash = expected_body_hash('payload')

        with patch('oauth1.coreutils.get_nonce', return_value='fixednonce123456'), \
                patch('oauth1.coreutils.get_timestamp', return_value=1700000000), \
                patch('oauth1.oauth.OAuth.sign_message', return_value='fixed+/sig='):
            request = signer.sign_request(SignerTest.uri, request)

        self.assertEqual(
            'OAuth oauth_consumer_key="dummy",oauth_nonce="fixednonce123456",'
            'oauth_timestamp="1700000000",oauth_signature_method="RSA-PSS",oauth_version="1.0",'
            f'oauth_body_hash="{body_hash}",'
            'oauth_signature="fixed%2B%2Fsig%3D"',
            request.headers['Authorization'],
        )

    def test_sign_request_with_default_signature_method_snapshot_header(self):
        request = Request()
        request.method = 'POST'
        request.data = 'payload'
        request.headers = {}
        signer = OAuthSigner(SignerTest.consumer_key, SignerTest.signing_key)

        body_hash = expected_body_hash('payload')

        with patch('oauth1.coreutils.get_nonce', return_value='fixednonce123456'), \
                patch('oauth1.coreutils.get_timestamp', return_value=1700000000), \
                patch('oauth1.oauth.OAuth.sign_message', return_value='fixed+/sig='):
            request = signer.sign_request(SignerTest.uri, request)

        self.assertEqual(
            'OAuth oauth_consumer_key="dummy",oauth_nonce="fixednonce123456",'
            'oauth_timestamp="1700000000",oauth_signature_method="RSA-SHA256",oauth_version="1.0",'
            f'oauth_body_hash="{body_hash}",'
            'oauth_signature="fixed%2B%2Fsig%3D"',
            request.headers['Authorization'],
        )

    @patch.object(Session, 'send')
    def test_sign_prepared_request(self, mock_send):
        class MCSigner(AuthBase):
            def __init__(self, consumer_key, signing_key):
                self.signer = OAuthSigner(consumer_key, signing_key)

            def __call__(self, request):
                self.signer.sign_request(request.url, request)
                return request

        signer = MCSigner(SignerTest.consumer_key, SignerTest.signing_key)
        requests.get(SignerTest.uri, auth=signer)

        auth_header = (
            mock_send.call_args[0][0].headers if isinstance(mock_send.call_args, tuple) else mock_send.call_args.args
            [0].headers)['Authorization']

        self.assertTrue("OAuth" in auth_header)
        self.assertTrue("oauth_consumer_key=\"dummy\"" in auth_header)


if __name__ == '__main__':
    unittest.main()
