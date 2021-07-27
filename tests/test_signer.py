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
from requests import Request
from oauth1.signer import OAuthSigner
import oauth1.authenticationutils as authenticationutils


class SignerTest(unittest.TestCase):

    def test_sign_request(self):
        signing_key = authenticationutils.load_signing_key('./test_key_container.p12', "Password1")
        consumer_key = 'dummy'
        uri = "https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0"

        request = Request()
        request.method = "POST"
        request.data = ""

        signer = OAuthSigner(consumer_key, signing_key)
        request = signer.sign_request(uri, request)
        auth_header = request.headers['Authorization']
        self.assertTrue("OAuth" in auth_header)
        self.assertTrue("dummy" in auth_header)


if __name__ == '__main__':
    unittest.main()
