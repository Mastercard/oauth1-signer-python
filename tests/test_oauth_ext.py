#!/usr/bin/env python
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
import time
from OpenSSL import crypto
from requests import PreparedRequest
from uuid import uuid4

import oauth1.authenticationutils as authenticationutils
from oauth1 import coreutils as util
from oauth1.oauth_ext import HASH_SHA256
from oauth1.oauth_ext import OAuth1RSA


class OAuthExtTest(unittest.TestCase):
    signing_key = authenticationutils.load_signing_key('./test_key_container.p12', "Password1")
    consumer_key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    data = 'sensistive data'
    mock_prepared_request = PreparedRequest()
    mock_prepared_request.prepare(headers={'Content-type': 'application/json', 'Accept': 'application/json'},
                                  method="POST",
                                  url="http://www.example.com")
    payload = {
        'oauth_version': '1.0',
        'oauth_nonce': str(uuid4()),
        'oauth_timestamp': str(int(time.time())),
        'oauth_signature_method': 'RSA-SHA256',
        'oauth_consumer_key': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    }

    payload_ext = {'oauth_version': '1.0', 'oauth_nonce': 'xxxx213-1111-xx00-11xx-xxxx12xxxx12',
                   'oauth_timestamp': '1111111111', 'oauth_signature_method': 'RSA-SHA256',
                   'oauth_consumer_key': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                   'oauth_body_hash': 'SamplEOaUthBoDYhASh', 'oauth_signature': 'OauTHSinaTUrESaMPle=='}

    def test_oauth_body_hash_with_body_string(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = "{'A' : 'sensistive data'}"

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(OAuthExtTest.mock_prepared_request, OAuthExtTest.payload)

        # Using mock data to find the hash value
        hashlib_val = hashlib.sha256((OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_bytes(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = b'{"A" : OAuthExtTest.data}'

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(OAuthExtTest.mock_prepared_request, OAuthExtTest.payload)

        # Using mock data to find the hash value
        hashlib_val = hashlib.sha256(OAuthExtTest.mock_prepared_request.body).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_empty(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = ''

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(OAuthExtTest.mock_prepared_request, OAuthExtTest.payload)

        # Using mock data to find the hash value
        hashlib_val = hashlib.sha256(str(OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_none(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        OAuthExtTest.mock_prepared_request.body = None

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(OAuthExtTest.mock_prepared_request, OAuthExtTest.payload)

        # Using mock data to find the hash value
        hashlib_val = hashlib.sha256(str(OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)

    def test_oauth_body_hash_with_body_multipart(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        mock_request = PreparedRequest()
        mock_request.prepare(headers={'Content-type': 'multipart/form-data'},
                             method="GET",
                             url="http://www.mastercard.com")

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(mock_request, OAuthExtTest.payload)

        # Using mock data to find the hash value
        hashlib_val = hashlib.sha256(str(OAuthExtTest.mock_prepared_request.body).encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)

    def test_signature(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        oauth_signature_object = oauth_object.signature(OAuthExtTest.data)
        signature = util.base64_encode(crypto.sign(OAuthExtTest.signing_key, OAuthExtTest.data, HASH_SHA256))
        self.assertEqual(signature, oauth_signature_object)

    def test_get_nonce(self):
        nonce = OAuth1RSA.nonce()
        self.assertEqual(len(nonce), 36)

    def test_get_timestamp(self):
        timestamp = OAuth1RSA.timestamp()
        self.assertEqual(len(str(timestamp)), 10)

    def test_helper_hash_string(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        hash_object = oauth_object._hash(OAuthExtTest.data)
        self.assertEqual(hash_object,
                         b'\xe8@\x97\xa0\x07H\x0b\xb2\x81"1\xcb\xf8\xa6@|&\xb9\xd7\xdf.\x80\xa9\x0b\xed,\x8f2\x88\xd7\xf7\xe5')

    def test_helper_hash_bytes(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        hash_object = oauth_object._hash(b"value in bytes")
        self.assertEqual(hash_object,
                         b'\\\n\x0e\xa3\xfe\x01\xd6T\x9fE\x97\x06\x937\x9d\\\xeaSz^\xe8\xab\xb1\xff:n\x9bY\xf5iV|')

    def test_helper_hash_nonetype(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        hash_object = oauth_object._hash('')
        self.assertEqual(hash_object,
                         b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U")

    def test_signable_message(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        signable_message = oauth_object.signable_message(OAuthExtTest.mock_prepared_request, OAuthExtTest.payload_ext)
        self.assertTrue(OAuthExtTest.mock_prepared_request.method in signable_message)

    def test_helper_generate_header(self):
        generate_header = OAuth1RSA._generate_header(OAuthExtTest.payload_ext)
        self.assertTrue("OAuth" in generate_header)

    def test_call(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key)
        call_object = oauth_object.__call__(OAuthExtTest.mock_prepared_request)
        self.assertTrue("Authorization" in call_object.headers)


if __name__ == '__main__':
    unittest.main()
