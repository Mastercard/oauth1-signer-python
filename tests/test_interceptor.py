#!/usr/bin/env python
# -*- coding: utf-8 -*-#
#
#
# Copyright (c) 2019 MasterCard International Incorporated
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
from urllib.parse import urlencode
from oauth1.oauth import OAuth
from oauth1.signer_interceptor import SignerInterceptor
import oauth1.authenticationutils as authenticationutils
from os.path import dirname, realpath, join, os
from oauth1.signer import OAuthSigner
from oauth1.signer_interceptor import add_signing_layer
from oauth1.signer_interceptor import get_signing_layer


class OAuthInterceptorTest(unittest.TestCase):


    """ add an interceptor, check api client has changed """
    def test_add_interceptor(self):
        if os.path.exists('./test_key_container.p12'):
            key_file = './test_key_container.p12'
            key_password = "Password1"
            consumer_key = 'uLXKmWNmIkzIGKfA2injnNQqpZaxaBSKxa3ixEVu2f283c95!33b9b2bd960147e387fa6f3f238f07170000000000000000'

            signing_layer1 = get_signing_layer(self, requests)
            add_signing_layer(self, requests, key_file, key_password, consumer_key)
            signing_layer2 = get_signing_layer(self, requests)
            self.assertNotEqual(signing_layer1, signing_layer2)            
        else:
            print("Please add a ./test_key_container.p12 file to enable key tests")



    """ these will fail because the test keys can't access the service, you'll need to insert a valid key file, password, and consumer key """
    def localonly_test_without_interceptor(self):
        if os.path.exists('./test_key_container.p12'):
            key_file = './test_key_container.p12'
            key_password = "Password1"
            consumer_key = 'uLXKmWNmIkzIGKfA2injnNQqpZaxaBSKxa3ixEVu2f283c95!33b9b2bd960147e387fa6f3f238f07170000000000000000'
            signing_key = authenticationutils.load_signing_key(key_file, key_password)

            baseUrl = 'https://sandbox.api.mastercard.com'

            queryMap = {
                "Format": "JSON", # change this to toggle between and XML or JSON response
                "fxDate": "2016-09-30",
                "transCurr": "ALL",
                "crdhldBillCurr": "DZD",
                "bankFee": "5",
                "transAmt": "23"
            }

            uri = baseUrl + "/settlement/currencyrate/conversion-rate?" + urlencode(queryMap)
            header = OAuth().get_authorization_header(uri, 'GET', None, consumer_key, signing_key)
            headers = {'Authorization': header, 'Content-Type': 'application/json'}

            r = requests.get(uri, headers=headers)
            print(r.text)

    """ these will fail because the test keys can't access the service, you'll need to insert a valid key file, password, and consumer key """
    def localonly_test_with_interceptor(self):
        if os.path.exists('./test_key_container.p12'):
            key_file = './test_key_container.p12'
            key_password = "Password1"
            consumer_key = 'uLXKmWNmIkzIGKfA2injnNQqpZaxaBSKxa3ixEVu2f283c95!33b9b2bd960147e387fa6f3f238f07170000000000000000'
            signing_key = authenticationutils.load_signing_key(key_file, key_password)

            baseUrl = 'https://sandbox.api.mastercard.com'

            test_cli = APIClientForTest()
            add_signing_layer(self, test_cli, key_file, key_password, consumer_key)

            queryMap = {
                "Format": "JSON", # change this to toggle between and XML or JSON response
                "fxDate": "2016-09-30",
                "transCurr": "ALL",
                "crdhldBillCurr": "DZD",
                "bankFee": "5",
                "transAmt": "23"
            }

            uri = baseUrl + "/settlement/currencyrate/conversion-rate"

            r = test_cli.request('GET', uri, query_params=queryMap)
            print(r.text)


if __name__ == '__main__':
    unittest.main()



class APIClientForTest():


    def request(self, method, uri, query_params=None, headers=None, post_params=None, body=None, _preload_content=True, _request_timeout=None):
        res = None

        if query_params:
            uri += '?' + urlencode(query_params)

        if method == 'GET':
            res = requests.get(uri, headers=headers)
        if method == 'POST':
            res = requests.post(uri, headers=headers, body=body)

        return res
