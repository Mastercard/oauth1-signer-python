#!/usr/bin/env python
# -*- coding: utf-8 -*- 
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
"""
Utility file having common functions
"""

import hashlib
import base64
import re

from urllib.parse import urlparse, quote, quote_plus, parse_qsl

def validate_url(url):
    """
    Validates that the given string is a valid URL
    """
    url_regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if url_regex.match(url):
        return True
    return False


def normalize_params(url, params):
    """
    Combines the query parameters of url and extra params into a single queryString.
    All the query string parameters are lexicographically sorted
    """
    # parse the url
    parse = urlparse(url)

    # Get the query list
    qs_list = parse_qsl(parse.query, keep_blank_values=True)
    if params is None:
        combined_list = qs_list
    else:
        combined_list = list(qs_list)
        combined_list += params.items()

    # Needs to be encoded before sorting
    encoded_list = [encode_pair(key, value) for (key, value) in combined_list]
    sorted_list = sorted(encoded_list, key=lambda x:x)

    return "&".join(sorted_list)


def encode_pair(key, value):
    encoded_key = oauth_query_string_element_encode(key)
    encoded_value = oauth_query_string_element_encode(value if isinstance(value, bytes) else str(value))
    return "%s=%s" % (encoded_key, encoded_value)

def oauth_query_string_element_encode(value):
    """
    RFC 3986 encodes the value

    Note. This is based on RFC3986 but according to https://tools.ietf.org/html/rfc5849#section-3.6
    it replaces space with %20 not "+".
    """
    encoded = quote(value)
    encoded = str.replace(encoded, ':', '%3A')
    encoded = str.replace(encoded, '+', '%2B')
    encoded = str.replace(encoded, '*', '%2A')
    return encoded

def normalize_url(url):
    """
    Removes the query parameters from the URL
    """
    parse = urlparse(url)

    # netloc should be lowercase
    netloc = parse.netloc.lower()
    if parse.scheme=="http":
        if netloc.endswith(":80"):
            netloc = netloc[:-3]

    elif parse.scheme=="https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # add a '/' at the end of the netloc if there in no path
    if not parse.path:
        netloc = netloc+"/"

    return "{}://{}{}".format(parse.scheme, netloc, parse.path)


def uri_rfc3986_encode(value):
    """
    RFC 3986 encodes the value
    """
    encoded = quote_plus(value)
    encoded = str.replace(encoded, ':', '%3A')
    encoded = str.replace(encoded, '+', '%2B')
    encoded = str.replace(encoded, '*', '%2A')
    return encoded


def sha256_encode(text):
    """
    Returns the digest of SHA-256 of the text
    """
    return hashlib.sha256(str(text).encode('utf-8')).digest()


def base64_encode(text):
    """
    Base64 encodes the given input
    """
    encode = base64.b64encode(text)
    if isinstance(encode, (bytearray, bytes)):
        return encode.decode('ascii')
    else:
        return encode
