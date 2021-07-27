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
import json
import oauth1.coreutils as util
from OpenSSL import crypto


class OAuth:
    EMPTY_STRING = ""

    @staticmethod
    def get_authorization_header(uri, method, payload, consumer_key, signing_key):
        oauth_parameters = OAuth.get_oauth_parameters(uri, method, payload, consumer_key, signing_key)

        # Get the updated base parameters dict
        oauth_base_parameters_dict = oauth_parameters.get_base_parameters_dict()

        # Generate the header value for OAuth Header
        oauth_key = OAuthParameters.OAUTH_KEY + " " + ",".join(
            [str(key) + "=\"" + str(value) + "\"" for (key, value) in oauth_base_parameters_dict.items()])
        return oauth_key

    @staticmethod
    def get_oauth_parameters(uri, method, payload, consumer_key, signing_key):
        # Get all the base parameters such as nonce and timestamp
        oauth_parameters = OAuthParameters()
        oauth_parameters.set_oauth_consumer_key(consumer_key)
        oauth_parameters.set_oauth_nonce(util.get_nonce())
        oauth_parameters.set_oauth_timestamp(util.get_timestamp())
        oauth_parameters.set_oauth_signature_method("RSA-SHA256")
        oauth_parameters.set_oauth_version("1.0")

        payload_str = json.dumps(payload) if type(payload) is dict or type(payload) is list else payload
        if not payload_str:
            # If the request does not have an entity body, the hash should be taken over the empty string
            payload_str = OAuth.EMPTY_STRING

        encoded_hash = util.base64_encode(util.sha256_encode(payload_str))
        oauth_parameters.set_oauth_body_hash(encoded_hash)

        # Get the base string
        base_string = OAuth.get_base_string(uri, method, oauth_parameters.get_base_parameters_dict())

        # Sign the base string using the private key
        signature = OAuth.sign_message(base_string, signing_key)

        # Set the signature in the Base parameters
        oauth_parameters.set_oauth_signature(util.percent_encode(signature))

        return oauth_parameters

    @staticmethod
    def get_base_string(url, method, oauth_parameters):
        merge_params = oauth_parameters.copy()
        return "{}&{}&{}".format(method.upper(),
                                 util.percent_encode(util.normalize_url(url)),
                                 util.percent_encode(util.normalize_params(url, merge_params)))

    @staticmethod
    def sign_message(message, signing_key):
        #    Signs the message using the private signing key
        sign = crypto.sign(signing_key, message.encode("utf-8"), 'SHA256')
        return util.base64_encode(sign)


class OAuthParameters(object):
    """
    Stores the OAuth parameters required to generate the Base String and Headers constants
    """

    OAUTH_BODY_HASH_KEY = "oauth_body_hash"
    OAUTH_CONSUMER_KEY = "oauth_consumer_key"
    OAUTH_NONCE_KEY = "oauth_nonce"
    OAUTH_KEY = "OAuth"
    AUTHORIZATION = "Authorization"
    OAUTH_SIGNATURE_KEY = "oauth_signature"
    OAUTH_SIGNATURE_METHOD_KEY = "oauth_signature_method"
    OAUTH_TIMESTAMP_KEY = "oauth_timestamp"
    OAUTH_VERSION = "oauth_version"

    def __init__(self):
        self.base_parameters = {}

    def put(self, key, value):
        self.base_parameters[key] = value

    def get(self, key):
        return self.base_parameters[key]

    def set_oauth_consumer_key(self, consumer_key):
        self.put(OAuthParameters.OAUTH_CONSUMER_KEY, consumer_key)

    def get_oauth_consumer_key(self):
        return self.get(OAuthParameters.OAUTH_CONSUMER_KEY)

    def set_oauth_nonce(self, oauth_nonce):
        self.put(OAuthParameters.OAUTH_NONCE_KEY, oauth_nonce)

    def get_oauth_nonce(self):
        return self.get(OAuthParameters.OAUTH_NONCE_KEY)

    def set_oauth_timestamp(self, timestamp):
        self.put(OAuthParameters.OAUTH_TIMESTAMP_KEY, timestamp)

    def get_oauth_timestamp(self):
        return self.get(OAuthParameters.OAUTH_TIMESTAMP_KEY)

    def set_oauth_signature_method(self, signature_method):
        self.put(OAuthParameters.OAUTH_SIGNATURE_METHOD_KEY, signature_method)

    def get_oauth_signature_method(self):
        return self.get(OAuthParameters.OAUTH_SIGNATURE_METHOD_KEY)

    def set_oauth_signature(self, signature):
        self.put(OAuthParameters.OAUTH_SIGNATURE_KEY, signature)

    def get_oauth_signature(self):
        return self.get(OAuthParameters.OAUTH_SIGNATURE_KEY)

    def set_oauth_body_hash(self, body_hash):
        self.put(OAuthParameters.OAUTH_BODY_HASH_KEY, body_hash)

    def get_oauth_body_hash(self):
        return self.get(OAuthParameters.OAUTH_BODY_HASH_KEY)

    def set_oauth_version(self, version):
        self.put(OAuthParameters.OAUTH_VERSION, version)

    def get_oauth_version(self):
        return self.get(OAuthParameters.OAUTH_VERSION)

    def get_base_parameters_dict(self):
        return self.base_parameters
