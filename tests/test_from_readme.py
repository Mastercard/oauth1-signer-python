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
from oauth1.oauth import OAuth
import oauth1.authenticationutils as authenticationutils
from os.path import dirname, realpath, join, os
from oauth1.signer import OAuthSigner


class OAuthReadmeTest(unittest.TestCase):


    """ can't call the service because the test keys can't access the service, you'll need to insert a valid key file, password, and consumer key """
    def test_from_readme(self):
        if os.path.exists('./test_key_container.p12'):
            uri = "https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0"
            method = "POST"

            signing_key = authenticationutils.load_signing_key("./test_key_container.p12", "Password1")
            consumer_key = OAuthSigner("uLXKmWNmIkzIGKfA2injnNQqpZaxaBSKxa3ixEVu2f283c95!33b9b2bd960147e387fa6f3f238f07170000000000000000", signing_key)

            header = OAuth().get_authorization_header(uri, method, "payload", consumer_key, signing_key)
        else:
            print("Please add a ./test_key_container.p12 file to enable key tests")



if __name__ == '__main__':
    unittest.main()
