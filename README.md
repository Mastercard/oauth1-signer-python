# oauth1-signer-python

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-light.svg">
  <img src="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg" alt="mastercard developers logo">
</picture>

[![](https://github.com/Mastercard/oauth1-signer-python/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/oauth1-signer-python/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_oauth1-signer-python&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_oauth1-signer-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_oauth1-signer-python&metric=coverage)](https://sonarcloud.io/dashboard?id=Mastercard_oauth1-signer-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_oauth1-signer-python&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Mastercard_oauth1-signer-python)
[![](https://github.com/Mastercard/oauth1-signer-python/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/oauth1-signer-python/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/pypi/v/mastercard-oauth1-signer.svg?style=flat&color=blue)](https://pypi.org/project/mastercard-oauth1-signer)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/oauth1-signer-python/blob/master/LICENSE)


## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [Supported Signature Methods](#supported-signature-methods)
  * [References](#references)
  * [Versioning and Deprecation Policy](#versioning)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Importing the Code](#importing-the-code)
  * [Loading the Signing Key](#loading-the-signing-key) 
  * [Creating the OAuth Authorization Header](#creating-the-oauth-authorization-header)
  * [Signing HTTP Client Request Objects](#signing-http-client-request-objects)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Python library for generating a Mastercard API compliant OAuth signature.

### Compatibility <a name="compatibility"></a>
| Version                | Python | Status | Notes |
|------------------------|--------|--------|-------|
| **1.9.2**              | 3.8, 3.9, 3.10, 3.11, 3.12 | Current | Maintenance & security fixes |
| **2.0.0** (coming soon) | 3.10, 3.11, 3.12 | Planned | Drops 3.8/3.9 support |

⚠️ **Deprecation Notice:** Python 3.8 (EOL Oct 2024) and 3.9 (EOL Oct 2025) support will be removed in v2.0.0.
Python 3.8 and 3.9 are deprecated and will be removed in v2.0.0 (Python 3.10+ only).
A `DeprecationWarning` is emitted when importing this package on Python 3.8/3.9.

Release notes: see [CHANGELOG.md](CHANGELOG.md) (or GitHub Releases).

### Supported Signature Methods <a name="supported-signature-methods"></a>
Two cryptographic methods are available for generating OAuth signatures, selected via the `SignatureMethod` enum:

**Important:** the `signature_method` parameter expects a **`SignatureMethod` enum member**. Do not pass raw strings
(e.g. `"RSA-SHA256"`, `"RSA-PSS-SHA256"`).

| Enum Value | Algorithm | Specification |
|---|---|---|
| `SignatureMethod.RSA_SHA256` (default) | RSASSA-PKCS1-v1_5 with SHA-256 | [RFC 8017 §8.2](https://tools.ietf.org/html/rfc8017#section-8.2) |
| `SignatureMethod.RSA_PSS_SHA256` | RSASSA-PSS (Digest: SHA-256, MGF: MGF1 with SHA-256, Salt length: 32 bytes) | [RFC 8017 §8.1](https://tools.ietf.org/html/rfc8017#section-8.1) |

`OAuth.get_authorization_header` accepts an optional `signature_method` parameter. When omitted, `SignatureMethod.RSA_SHA256` is used by default. See the usage examples below for both the default flow and explicit `RSA_PSS_SHA256` calls.

### References <a name="references"></a>
* [OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)
* [Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

### Versioning and Deprecation Policy <a name="versioning"></a>
* [Mastercard Versioning and Deprecation Policy](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive credentials for your app:
* A consumer key (displayed on the Mastercard Developer Portal)
* A private request signing key (matching the public certificate displayed on the Mastercard Developer Portal)

### Adding the Library to Your Project <a name="adding-the-library-to-your-project"></a>

```
pip install mastercard-oauth1-signer
```
### Importing the Code <a name="importing-the-code"></a>

``` python
import oauth1.authenticationutils as authenticationutils
from oauth1.oauth import OAuth, SignatureMethod
```
### Loading the Signing Key <a name="loading-the-signing-key"></a>

A private key object can be created by calling the `authenticationutils.load_signing_key` method:
``` python
signing_key = authenticationutils.load_signing_key('<insert PKCS#12 key file path>', '<insert key password>')
```

### Creating the OAuth Authorization Header <a name="creating-the-oauth-authorization-header"></a>
The method that does all the heavy lifting is `OAuth.get_authorization_header`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header.

If you do not provide `signature_method`, `SignatureMethod.RSA_SHA256` is used by default.

#### POST example

```python
consumer_key = '<insert consumer key>'
uri = 'https://sandbox.api.mastercard.com/service'
payload = 'Hello world!'
authHeader = OAuth.get_authorization_header(uri, 'POST', payload, consumer_key, signing_key)
```

#### GET example
```python
consumer_key = '<insert consumer key>'
uri = 'https://sandbox.api.mastercard.com/service'
authHeader = OAuth.get_authorization_header(uri, 'GET', None, consumer_key, signing_key)
```

#### POST example with RSA-PSS

```python
consumer_key = '<insert consumer key>'
uri = 'https://sandbox.api.mastercard.com/service'
payload = 'Hello world!'
authHeader = OAuth.get_authorization_header(
    uri,
    'POST',
    payload,
    consumer_key,
    signing_key,
    signature_method=SignatureMethod.RSA_PSS_SHA256,
)
```

  #### GET example with RSA-PSS

  ```python
  consumer_key = '<insert consumer key>'
  uri = 'https://sandbox.api.mastercard.com/service'
  authHeader = OAuth.get_authorization_header(
    uri,
    'GET',
    None,
    consumer_key,
    signing_key,
    signature_method=SignatureMethod.RSA_PSS_SHA256,
  )
  ```

#### Use of authHeader with requests module (POST and GET example)
```python
headerdict = {'Authorization' : authHeader}
requests.post(uri, headers=headerdict, data=payload)
requests.get(uri, headers=headerdict)
```

### Signing HTTP Client Request Objects <a name="signing-http-client-request-objects"></a>

Alternatively, you can use helper classes for some of the commonly used HTTP clients.

These classes will modify the provided request object in-place and will add the correct `Authorization` header. Once instantiated with a consumer key and private key, these objects can be reused. 

Usage briefly described below, but you can also refer to the test project for examples. 

+ [Requests: HTTP for Humans™](#requests)

#### Requests: HTTP for Humans™ <a name="requests"></a>

You can sign [request](https://requests.readthedocs.io/en/latest/user/quickstart#make-a-request) objects using the `OAuthSigner` class. 

Usage:
```python
from oauth1.signer import OAuthSigner

uri = "https://sandbox.api.mastercard.com/service"
request = Request()
request.method = "POST"
# …

signer = OAuthSigner(consumer_key, signing_key)
request = signer.sign_request(uri, request)
```

When `signature_method` is omitted, `OAuthSigner` uses `SignatureMethod.RSA_SHA256`.

To use RSA-PSS instead of the default RSA-SHA256:

```python
from oauth1.oauth import SignatureMethod
from oauth1.signer import OAuthSigner

signer = OAuthSigner(
    consumer_key,
    signing_key,
    signature_method=SignatureMethod.RSA_PSS_SHA256,
)
request = signer.sign_request(uri, request)
```


#### Usage of the `oauth_ext`
The requests library supports custom authentication extensions, with which the procedure of creating and calling such requests can simplify the process of request signing. Please, see the examples below:

###### POST example

```python
from oauth1.oauth_ext import OAuth1RSA
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth = OAuth1RSA(consumer_key, signing_key)
header = {'Content-type' : 'application/json', 'Accept' : 'application/json'}

# Passing payload for data parameter as string
payload = '{"key" : "value"}'
response = requests.post(uri, data=payload, auth=oauth, headers=header)

# Passing payload for data parameter as Json object
payload = {'key' : 'value'}
response = requests.post(uri, data=json.dumps(payload), auth=oauth, headers=header)

# Passing payload for json parameter Json object
payload = {'key' : 'value'}
response = requests.post(uri, json=payload, auth=oauth, headers=header)
```

###### GET example

```python
from oauth1.oauth_ext import OAuth1RSA
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth = OAuth1RSA(consumer_key, signing_key)

# Operation for get call
response = requests.get(uri, auth=oauth)
```

When `signature_method` is omitted, `OAuth1RSA` uses `SignatureMethod.RSA_SHA256`.

###### POST example with RSA-PSS

```python
from oauth1.oauth_ext import OAuth1RSA
from oauth1.oauth import SignatureMethod
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth_auth = OAuth1RSA(
    consumer_key,
    signing_key,
    signature_method=SignatureMethod.RSA_PSS_SHA256,
)
header = {'Content-type' : 'application/json', 'Accept' : 'application/json'}
payload = '{"key" : "value"}'
response = requests.post(uri, data=payload, auth=oauth_auth, headers=header)
```

###### GET example with RSA-PSS

```python
from oauth1.oauth_ext import OAuth1RSA
from oauth1.oauth import SignatureMethod
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth = OAuth1RSA(consumer_key, signing_key, signature_method=SignatureMethod.RSA_PSS_SHA256)
response = requests.get(uri, auth=oauth)
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

This project provides you with classes you can use when configuring your API client. These classes will take care of adding the correct `Authorization` header before sending the request.

Generators currently supported:
+ [python](#python)

#### python <a name="python"></a>

##### OpenAPI Generator

Client libraries can be generated using the following command:
```shell
openapi-generator-cli generate -i openapi-spec.yaml -g python -o out
```
See also:
* [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation/)
* [CONFIG OPTIONS for python](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/python.md)

##### Usage of the `oauth1.signer_interceptor`

```python
import openapi_client
from oauth1.signer_interceptor import add_signer_layer

# …
config = openapi_client.Configuration()
config.host = 'https://sandbox.api.mastercard.com'
client = openapi_client.ApiClient(config)
add_signer_layer(client, '<insert PKCS#12 key file path>', '<insert key password>', '<insert consumer key>')
some_api = openapi_client.SomeApi(client)
result = some_api.do_something()
# …
```

When `signature_method` is omitted, `add_signer_layer` uses `SignatureMethod.RSA_SHA256`.

To use RSA-PSS with an OpenAPI Generator client:

```python
import openapi_client
from oauth1.oauth import SignatureMethod
from oauth1.signer_interceptor import add_signer_layer

config = openapi_client.Configuration()
config.host = 'https://sandbox.api.mastercard.com'
client = openapi_client.ApiClient(config)
add_signer_layer(
    client,
    '<insert PKCS#12 key file path>',
    '<insert key password>',
    '<insert consumer key>',
    signature_method=SignatureMethod.RSA_PSS_SHA256,
)
```
