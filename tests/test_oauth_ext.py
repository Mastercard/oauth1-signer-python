#!/usr/bin/env python
# -*- coding: utf-8 -*-#
#
#
# Copyright (c) 2020 MasterCard International Incorporated
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
from oauth1.oauth import OAuth
from oauth1.oauth import OAuthParameters
import oauth1.authenticationutils as authenticationutils
import oauth1.coreutils as Util
from oauth1.signer import OAuthSigner
from oauth1.oauth_ext import OAuth1RSA
from oauth1.oauth_ext import HASH_SHA256
import pprint
import requests
from requests import PreparedRequest
import json
from uuid import uuid4
import time
from oauth1 import coreutils as util
import hashlib


class OAuthExtTest(unittest.TestCase):

    signing_key = authenticationutils.load_signing_key('./test_key_container.p12', "Password1")
    consumer_key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    payload = {'oauth_version': '1.0', 'oauth_nonce': 'xxxx213-1111-xx00-11xx-xxxx12xxxx12', 'oauth_timestamp': '1111111111', 'oauth_signature_method': 'RSA-SHA256', 'oauth_consumer_key': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'oauth_body_hash': 'SamplEOaUthBoDYhASh', 'oauth_signature': 'OauTHSinaTUrESaMPle=='}
    
    payload = {
            'oauth_version': '1.0',
            'oauth_nonce': str(uuid4()),
            'oauth_timestamp': str(int(time.time())),
            'oauth_signature_method': 'RSA-SHA256',
            'oauth_consumer_key': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
        }


    def test_oauth_body_hash_with_body_string(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        mock_prepared_request = MockPreparedRequest()

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(mock_prepared_request , OAuthExtTest.payload)

        # Using mock data to find the hash value
        body = mock_prepared_request.body
        hashlib_val = hashlib.sha256(body.encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)


    def test_oauth_body_hash_with_body_bytes(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        mock_prepared_request = MockPreparedRequest()
        mock_prepared_request.body = b'{"A" : "sensistive data"}'

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(mock_prepared_request , OAuthExtTest.payload)

        # Using mock data to find the hash value
        body = mock_prepared_request.body
        hashlib_val = hashlib.sha256(body).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)


    def test_oauth_body_hash_with_body_none(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        mock_prepared_request = MockPreparedRequest()
        mock_prepared_request.body = None

        # Passing mock data to the actual func to get the value
        oauth_body_hash_object = oauth_object.oauth_body_hash(mock_prepared_request , OAuthExtTest.payload)

        # Using mock data to find the hash value
        body = mock_prepared_request.body
        hashlib_val = hashlib.sha256(str(body).encode('utf8')).digest()
        payload_hash_value = util.uri_rfc3986_encode(util.base64_encode(hashlib_val))

        self.assertEqual(oauth_body_hash_object['oauth_body_hash'], payload_hash_value)


    def test_signature(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        oauth_signature_object = oauth_object.signature('sensistive data')
        self.assertEqual("dFb859e5IOFj1vcQDa61y6Hz6bFQcgvS3OUxTyibbzm3LVP+NB0Qau7fFNrT5fkKal4Y6DyWpfIFMotK5sFNF6UCTpQqL71ItRFX9vB6ztEfohlkwMS4Jxem9foJ6uA3QrZzAx37Bz+Y6C/Qjoie9XmLbZfPgbPSupvVmTpu830elVYuGQq5dPOgvaIXX65syw2+PuVFVRpd62gSCS519VBsJz/Fkrp7XJdWm2sPvp8XbJyD7Yvvmlehem/3GlkDRCzOPLpxpgkKudPHc62WDvT9CTvop6uVCEOGwBlp30hGAJSPUR5rxmcCjTT5ypa8ldCNJkbPDdkKaPG2eGR85g==", oauth_signature_object)


    def test_get_nonce(self):
        nonce = OAuth1RSA.nonce()
        self.assertEqual(len(nonce),36)


    def test_get_timestamp(self):
        timestamp = OAuth1RSA.timestamp()
        self.assertEqual(len(str(timestamp)),10)


    def test_helper_hash_string(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        hash_object = oauth_object._hash('sensistive data')
        self.assertEqual(hash_object, b'\xe8@\x97\xa0\x07H\x0b\xb2\x81"1\xcb\xf8\xa6@|&\xb9\xd7\xdf.\x80\xa9\x0b\xed,\x8f2\x88\xd7\xf7\xe5')


    def test_helper_hash_bytes(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        hash_object = oauth_object._hash(b'sensistive data')
        self.assertEqual(hash_object, b'\xe8@\x97\xa0\x07H\x0b\xb2\x81"1\xcb\xf8\xa6@|&\xb9\xd7\xdf.\x80\xa9\x0b\xed,\x8f2\x88\xd7\xf7\xe5')


    def test_helper_hash_none(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        hash_object = oauth_object._hash(None)
        self.assertEqual(hash_object, b'\xdc\x93{Y\x89&\x04\xf5\xa8j\xc9i6\xcd\x7f\xf0\x9e%\xf1\x8a\xe6\xb7X\xe8\x01J$\xc7\xfa\x03\x9e\x91')


    def test_helper_hash_dict(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        hash_object = oauth_object._hash({'A':'sensistive data'})
        self.assertEqual(hash_object, b'\x87\xa0JR\x86\xae\xe9\xa4-\xb7\xba\xef6Z\x11\x1c\x00G\x9e\x1f(\xf8\xd5\xf8\xa8<\xda\x14\xa19*I')

    
    def test_signable_message(self):
        oauth_object = OAuth1RSA(OAuthExtTest.consumer_key, OAuthExtTest.signing_key, hash_alg=HASH_SHA256)
        mock_prepared_request = MockPreparedRequest()

        signable_message = oauth_object.signable_message(mock_prepared_request, OAuthExtTest.payload)
        self.assertTrue(mock_prepared_request.method in signable_message)


    def test_helper_generate_header(self):
        generate_header = OAuth1RSA._generate_header(OAuthExtTest.payload)
        self.assertTrue("OAuth" in generate_header)


class MockPreparedRequest():
    headers = {'Content-type':'application/json', 'Accept':'application/json'}
    body = "{'A' : 'sensistive data'}"
    method = "POST"
    url = "http://www.example.com"


if __name__ == '__main__':
    unittest.main()