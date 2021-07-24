# -*- coding: utf-8 -*-#
#
#
# Copyright 2019-2020 Mastercard
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
from unittest.mock import MagicMock

import oauth1.authenticationutils as authenticationutils
import oauth1.coreutils as util
from oauth1.oauth import OAuth
from oauth1.oauth import OAuthParameters

from concurrent.futures import ThreadPoolExecutor
import multiprocessing


class OAuthTest(unittest.TestCase):
    signing_key = authenticationutils.load_signing_key('./test_key_container.p12', "Password1")
    uri = 'https://www.example.com'

    def test_get_authorization_header_nominal(self):
        header = OAuth.get_authorization_header(OAuthTest.uri, 'POST', 'payload', 'dummy', OAuthTest.signing_key)
        self.assertTrue("OAuth" in header)
        self.assertTrue("dummy" in header)

    def test_get_authorization_header_should_compute_body_hash(self):
        header = OAuth.get_authorization_header(OAuthTest.uri, 'POST', '{}', 'dummy', OAuthTest.signing_key)
        self.assertTrue('RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=' in header)

    def test_get_authorization_header_should_return_empty_string_body_hash(self):
        header = OAuth.get_authorization_header(OAuthTest.uri, 'GET', None, 'dummy', OAuthTest.signing_key)
        self.assertTrue('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' in header)

    def test_get_nonce(self):
        nonce = util.get_nonce()
        self.assertEqual(len(nonce), 16)

    def test_get_timestamp(self):
        timestamp = util.get_timestamp()
        self.assertEqual(len(str(timestamp)), 10)

    def test_sign_message(self):
        base_string = 'POST&https%3A%2F%2Fsandbox.api.mastercard.com%2Ffraud%2Fmerchant%2Fv1%2Ftermination-inquiry' \
                      '&Format%3DXML%26PageLength%3D10%26PageOffset%3D0%26oauth_body_hash%3DWhqqH' \
                      '%252BTU95VgZMItpdq78BWb4cE%253D%26oauth_consumer_key' \
                      '%3Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%26oauth_nonce%3D1111111111111111111' \
                      '%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1111111111%26oauth_version%3D1.0'
        signature = OAuth.sign_message(base_string, OAuthTest.signing_key)
        signature = util.uri_rfc3986_encode(signature)
        self.assertEqual(signature,
                         "DvyS3R795sUb%2FcvBfiFYZzPDU%2BRVefW6X%2BAfyu%2B9fxjudQft"
                         "%2BShXhpounzJxYCwOkkjZWXOR0ICTMn6MOuG04TTtmPMrOxj5feGwD3leMBsi"
                         "%2B3XxcFLPi8BhZKqgapcAqlGfjEhq0COZ%2FF9aYDcjswLu0zgrTMSTp4cqXYMr9mbQVB4HL"
                         "%2FjiHni5ejQu9f6JB9wWW%2BLXYhe8F6b4niETtzIe5o77%2B"
                         "%2BkKK67v9wFIZ9pgREz7ug8K5DlxX0DuwdUKFhsenA5z%2FNNCZrJE"
                         "%2BtLu0tSjuF5Gsjw5GRrvW33MSoZ0AYfeleh5V3nLGgHrhVjl5%2BiS40pnG2po%2F5hIAUT5ag%3D%3D")

    def test_oauth_parameters(self):
        uri = "https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0"
        method = "POST"
        parameters = OAuth.get_oauth_parameters(uri, method, 'payload', 'dummy', OAuthTest.signing_key)
        consumer_key = parameters.get_oauth_consumer_key()
        self.assertEqual("dummy", consumer_key)

    def test_query_parser(self):
        uri = "https://sandbox.api.mastercard.com/audiences/v1/getcountries?offset=0&offset=1&length=10&empty&odd="
        oauth_parameters = OAuthParameters()
        oauth_parameters_base = oauth_parameters.get_base_parameters_dict()
        merge_parameters = oauth_parameters_base.copy()
        query_params = util.normalize_params(uri, merge_parameters)
        self.assertEqual(query_params, "empty=&length=10&odd=&offset=0&offset=1")

    def test_query_parser_when_params_is_None(self):
        uri = "https://sandbox.api.mastercard.com/audiences/v1/getcountries"
        query_params = util.normalize_params(uri, None)
        self.assertEqual(query_params, '')

    def test_query_parser_encoding(self):
        uri = "https://sandbox.api.mastercard.com?param1=plus+value&param2=colon:value"
        oauth_parameters = OAuthParameters()
        oauth_parameters_base = oauth_parameters.get_base_parameters_dict()
        merge_parameters = oauth_parameters_base.copy()
        query_params = util.normalize_params(uri, merge_parameters)
        self.assertEqual(query_params, "param1=plus%20value&param2=colon%3Avalue")

    def test_nonce_length(self):
        nonce = util.get_nonce()
        self.assertEqual(16, len(nonce))

    def test_nonce_uniqueness(self):
        list_of_nonce = []

        def task():
            for _ in range(0, 100000):
                list_of_nonce.append(util.get_nonce())

        executor = ThreadPoolExecutor(multiprocessing.cpu_count())
        future = executor.submit(task)
        future.result()

        self.assertEqual(OAuthTest.list_duplicates(list_of_nonce), [])

    @staticmethod
    def list_duplicates(seq):
        seen = set()
        seen_add = seen.add
        # adds all elements it doesn't know yet to seen and all other to seen_twice
        seen_twice = set(x for x in seq if x in seen or seen_add(x))
        # turn the set into a list (as requested)
        return list(seen_twice)

    def test_params_string_rfc_example_1(self):
        uri = "https://sandbox.api.mastercard.com"

        oauth_parameters1 = OAuthParameters()
        oauth_parameters1.set_oauth_consumer_key("9djdj82h48djs9d2")
        oauth_parameters1.set_oauth_signature_method("HMAC-SHA1")
        oauth_parameters1.set_oauth_timestamp("137131201")
        oauth_parameters1.set_oauth_nonce("7d8f3e4a")

        oauth_parameters_base1 = oauth_parameters1.get_base_parameters_dict()
        merge_parameters1 = oauth_parameters_base1.copy()
        query_params1 = util.normalize_params(uri, merge_parameters1)

        self.assertEqual(
            "oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1"
            "&oauth_timestamp=137131201",
            query_params1)

    def test_params_string_rfc_example_2(self):
        uri = "https://sandbox.api.mastercard.com?b5=%3D%253D&a3=a&a3=2%20q&c%40=&a2=r%20b&c2="

        oauth_parameters2 = OAuthParameters()
        oauth_parameters_base2 = oauth_parameters2.get_base_parameters_dict()
        merge_parameters2 = oauth_parameters_base2.copy()
        query_params2 = util.normalize_params(uri, merge_parameters2)

        self.assertEqual("a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=", query_params2)

    def test_params_string_ascending_byte_value_ordering(self):
        url = "https://localhost?b=b&A=a&A=A&B=B&a=A&a=a&0=0"

        oauth_parameters = OAuthParameters()
        oauth_parameters_base = oauth_parameters.get_base_parameters_dict()
        merge_parameters = oauth_parameters_base.copy()
        norm_params = util.normalize_params(url, merge_parameters)

        self.assertEqual("0=0&A=A&A=a&B=B&a=A&a=a&b=b", norm_params)

    def test_signature_base_string(self):
        uri = "https://api.mastercard.com"
        base_uri = util.normalize_url(uri)

        oauth_parameters = OAuthParameters()
        oauth_parameters.set_oauth_body_hash("body/hash")
        oauth_parameters.set_oauth_nonce("randomnonce")

        base_string = OAuth.get_base_string(base_uri, "POST", oauth_parameters.get_base_parameters_dict())
        self.assertEqual(
            "POST&https%3A%2F%2Fapi.mastercard.com%2F&oauth_body_hash%3Dbody%2Fhash%26oauth_nonce%3Drandomnonce",
            base_string)

    def test_signature_base_string2(self):
        body = "<?xml version=\"1.0\" encoding=\"Windows-1252\"?><ns2:TerminationInquiryRequest " \
               "xmlns:ns2=\"http://mastercard.com/termination\"><AcquirerId>1996</AcquirerId" \
               "><TransactionReferenceNumber>1</TransactionReferenceNumber><Merchant><Name>TEST</Name" \
               "><DoingBusinessAsName>TEST</DoingBusinessAsName><PhoneNumber>5555555555</PhoneNumber><NationalTaxId" \
               ">1234567890</NationalTaxId><Address><Line1>5555 Test " \
               "Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode" \
               "><Country>USA</Country></Address><Principal><FirstName>John</FirstName><LastName>Smith</LastName" \
               "><NationalId>1234567890</NationalId><PhoneNumber>5555555555</PhoneNumber><Address><Line1>5555 Test " \
               "Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode" \
               "><Country>USA</Country></Address><DriversLicense><Number>1234567890</Number><CountrySubdivision>XX" \
               "</CountrySubdivision></DriversLicense></Principal></Merchant></ns2:TerminationInquiryRequest>"
        url = "https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0" \
              "&PageLength=10"
        method = "POST"

        oauth_parameters = OAuthParameters()
        oauth_parameters.set_oauth_consumer_key("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        oauth_parameters.set_oauth_nonce("1111111111111111111")
        oauth_parameters.set_oauth_timestamp("1111111111")
        oauth_parameters.set_oauth_version("1.0")
        oauth_parameters.set_oauth_body_hash("body/hash")
        encoded_hash = util.base64_encode(util.sha256_encode(body))
        oauth_parameters.set_oauth_body_hash(encoded_hash)

        base_string = OAuth.get_base_string(url, method, oauth_parameters.get_base_parameters_dict())
        expected = "POST&https%3A%2F%2Fsandbox.api.mastercard.com%2Ffraud%2Fmerchant%2Fv1%2Ftermination-inquiry" \
                   "&Format%3DXML%26PageLength%3D10%26PageOffset%3D0%26oauth_body_hash%3Dh2Pd7zlzEZjZVIKB4j94UZn" \
                   "%2FxxoR3RoCjYQ9%2FJdadGQ%3D%26oauth_consumer_key" \
                   "%3Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%26oauth_nonce%3D1111111111111111111" \
                   "%26oauth_timestamp%3D1111111111%26oauth_version%3D1.0"

        self.assertEqual(expected, base_string)

    def test_sign_signature_base_string_invalid_key(self):
        self.assertRaises(AttributeError, OAuth.sign_message, "some string", None)

    def test_sign_signature_base_string(self):
        expected_signature_string = "IJeNKYGfUhFtj5OAPRI92uwfjJJLCej3RCMLbp7R6OIYJhtwxnTkloHQ2bgV7fks4GT" \
                                    "/A7rkqrgUGk0ewbwIC6nS3piJHyKVc7rvQXZuCQeeeQpFzLRiH3rsb+ZS+AULK+jzDje4Fb" \
                                    "+BQR6XmxuuJmY6YrAKkj13Ln4K6bZJlSxOizbNvt+Htnx" \
                                    "+hNd4VgaVBeJKcLhHfZbWQxK76nMnjY7nDcM/2R6LUIR2oLG1L9m55WP3bakAvmOr392ulv1" \
                                    "+mWCwDAZZzQ4lakDD2BTu0ZaVsvBW+mcKFxYeTq7SyTQMM4lEwFPJ6RLc8jJJ" \
                                    "+veJXHekLVzWg4qHRtzNBLz1mA=="
        signing_string = OAuth.sign_message("baseString", OAuthTest.signing_key)
        self.assertEqual(expected_signature_string, signing_string)

    def test_url_normalization_rfc_examples1(self):
        uri = "https://www.example.net:8080"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://www.example.net:8080/", base_uri)

    def test_url_normalization_rfc_examples2(self):
        uri = "http://EXAMPLE.COM:80/r%20v/X?id=123"
        base_uri = util.normalize_url(uri)
        self.assertEqual("http://example.com/r%20v/X", base_uri)

    def test_url_normalization_redundant_ports1(self):
        uri = "https://api.mastercard.com:443/test?query=param"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://api.mastercard.com/test", base_uri)

    def test_url_normalization_redundant_ports2(self):
        uri = "http://api.mastercard.com:80/test"
        base_uri = util.normalize_url(uri)
        self.assertEqual("http://api.mastercard.com/test", base_uri)

    def test_url_normalization_redundant_ports3(self):
        uri = "https://api.mastercard.com:17443/test?query=param"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://api.mastercard.com:17443/test", base_uri)

    def test_url_normalization_remove_fragment(self):
        uri = "https://api.mastercard.com/test?query=param#fragment"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://api.mastercard.com/test", base_uri)

    def test_url_normalization_add_trailing_slash(self):
        uri = "https://api.mastercard.com"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://api.mastercard.com/", base_uri)

    def test_url_normalization_lowercase_scheme_and_host(self):
        uri = "HTTPS://API.MASTERCARD.COM/TEST"
        base_uri = util.normalize_url(uri)
        self.assertEqual("https://api.mastercard.com/TEST", base_uri)

    def test_body_hash1(self):
        oauth_parameters = OAuthParameters()
        encoded_hash = util.base64_encode(util.sha256_encode(OAuth.EMPTY_STRING))
        oauth_parameters.set_oauth_body_hash(encoded_hash)
        self.assertEqual("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", encoded_hash)

    def test_body_hash2(self):
        oauth_parameters = OAuthParameters()
        encoded_hash = util.base64_encode(util.sha256_encode(None))
        oauth_parameters.set_oauth_body_hash(encoded_hash)
        self.assertEqual("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", encoded_hash)

    def test_body_hash3(self):
        oauth_parameters = OAuthParameters()
        encoded_hash = util.base64_encode(util.sha256_encode("{\"foõ\":\"bar\"}"))
        oauth_parameters.set_oauth_body_hash(encoded_hash)
        self.assertEqual("+Z+PWW2TJDnPvRcTgol+nKO3LT7xm8smnsg+//XMIyI=", encoded_hash)

    def test_url_encode1(self):
        self.assertEqual("Format%3DXML", util.uri_rfc3986_encode("Format=XML"))

    def test_url_encode2(self):
        self.assertEqual("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D", util.uri_rfc3986_encode("WhqqH+TU95VgZMItpdq78BWb4cE="))

    def test_url_encode3(self):
        self.assertEqual("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D%26o",
                         util.uri_rfc3986_encode("WhqqH+TU95VgZMItpdq78BWb4cE=&o"))

    def test_get_oauth_nonce_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_NONCE_KEY, "abcde")
        val = oauth_parameters.get_oauth_nonce()
        self.assertEqual("abcde", val)

    def test_get_oauth_nonce_timestamp_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_TIMESTAMP_KEY, "abcde")
        val = oauth_parameters.get_oauth_timestamp()
        self.assertEqual("abcde", val)

    def test_get_oauth_signature_method_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_SIGNATURE_METHOD_KEY, "abcde")
        val = oauth_parameters.get_oauth_signature_method()
        self.assertEqual("abcde", val)

    def test_get_oauth_signature_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_SIGNATURE_KEY, "abcde")
        val = oauth_parameters.get_oauth_signature()
        self.assertEqual("abcde", val)

    def test_get_oauth_body_hash_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_BODY_HASH_KEY, "abcde")
        val = oauth_parameters.get_oauth_body_hash()
        self.assertEqual("abcde", val)

    def test_get_oauth_version_param(self):
        oauth_parameters = OAuthParameters()
        oauth_parameters.put(OAuthParameters.OAUTH_VERSION, "abcde")
        val = oauth_parameters.get_oauth_version()
        self.assertEqual("abcde", val)

    def test_backward_compatibility_with_static_method(self):
        header = OAuth().get_authorization_header(OAuthTest.uri, 'POST', 'payload', 'dummy', OAuthTest.signing_key)
        self.assertTrue("OAuth" in header)
        self.assertTrue("dummy" in header)

        header = OAuth.get_authorization_header(OAuthTest.uri, 'POST', 'payload', 'dummy', OAuthTest.signing_key)
        self.assertTrue("OAuth" in header)
        self.assertTrue("dummy" in header)

    def test_percent_encoding(self):
        self.assertEqual("Format%3DXML", util.percent_encode("Format=XML"))
        self.assertEqual("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D", util.percent_encode("WhqqH+TU95VgZMItpdq78BWb4cE="))
        self.assertEqual("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D%26o", util.percent_encode("WhqqH+TU95VgZMItpdq78BWb4cE=&o"))
        self.assertEqual("WhqqH%2BTU95VgZ~Itpdq78BWb4cE%3D%26o", util.percent_encode("WhqqH+TU95VgZ~Itpdq78BWb4cE=&o"))
        self.assertEqual("%2525%C2%A3%C2%A5a%2FEl%20Ni%C3%B1o%2F%25", util.percent_encode("%25£¥a/El Niño/%"))

    def test_valid_oauth_signature_with_percent(self):
        util.get_nonce = MagicMock(return_value='Wpe3LF09z1e3xQRI')
        util.get_timestamp = MagicMock(return_value=1626728330)
        auth_header = OAuth.get_authorization_header('https://api.mastercard.com/abc/%123/service?a=123&b=%2a2b3',
                                                     'GET', None,
                                                     'abc-abc-abc!123', OAuthTest.signing_key)

        self.assertEqual('OAuth oauth_consumer_key="abc-abc-abc!123",oauth_nonce="Wpe3LF09z1e3xQRI",'
                         'oauth_timestamp="1626728330",oauth_signature_method="RSA-SHA256",oauth_version="1.0",'
                         'oauth_body_hash="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",'
                         'oauth_signature="GFdvCNe14%2FQdPi6KLgdFtYnqz9QVsqlzRwT1P5wvZCgyBzfTol69SRz4cIkeDx'
                         '%2BIEeUfkbrPdVA9JPy0S9lgpMzs0KfIAX064Bz5mBbTni8NWD74ulN5eEDQRWB47BqEsvNPSJlJLGapVe'
                         'YFyRlcIU7xMU1e1lA%2FtPTTHDSmIBfq4CtpCPvYMcd7ywoiHsi4hfI0d%2BTGS9pe0ez00mkne8C3%2FAHt'
                         'uRIp564D02Hhl6s%2BTUGdUvlXTaFaIH9GVdZ15n%2FUcTCqSKFjorwA9guiJQlFpZtQy04BBD19VbN6%2F%2BS'
                         'JvMAnVFQM5FJhgZ%2F5T9OP9%2BmjXz47EhG9MAx3raBjIw%3D%3D"', auth_header)


if __name__ == '__main__':
    unittest.main()
