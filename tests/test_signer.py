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
from oauth1.signer import OAuthSigner


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
