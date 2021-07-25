# oauth1-signer-python
<img src="https://developer.mastercard.com/img/logo_cogs.svg" />

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
  * [References](#references)
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
Python 3.6+

### References <a name="references"></a>
* [OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)
* [Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

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
from oauth1.oauth import OAuth
```
### Loading the Signing Key <a name="loading-the-signing-key"></a>

A private key object can be created by calling the `authenticationutils.load_signing_key` method:
``` python
signing_key = authenticationutils.load_signing_key('<insert PKCS#12 key file path>', '<insert key password>')
```

### Creating the OAuth Authorization Header <a name="creating-the-oauth-authorization-header"></a>
The method that does all the heavy lifting is `OAuth.get_authorization_header`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header.

#### POST example

```python
uri = 'https://sandbox.api.mastercard.com/service'
payload = 'Hello world!'
authHeader = OAuth.get_authorization_header(uri, 'POST', payload, '<insert consumer key>', signing_key)
```

#### GET example
```python
uri = 'https://sandbox.api.mastercard.com/service'
authHeader = OAuth.get_authorization_header(uri, 'GET', None, '<insert consumer key>', signing_key)
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

You can sign [request](https://2.python-requests.org/en/v1.0.0/user/quickstart/#make-a-request) objects using the `OAuthSigner` class. 

Usage:
```python
uri = "https://sandbox.api.mastercard.com/service"
request = Request()
request.method = "POST"
# ...

signer = OAuthSigner(consumer_key, signing_key)
request = signer.sign_request(uri, request)
```


#### Usage of the `oauth_ext`
The requests library supports custom authentication extensions, with which the procedure of creating and calling such requests can simplify the process of request signing. Please, see the examples below:

###### POST example

```python
from oauth1.oauth_ext import OAuth1RSA
from oauth1.oauth_ext import HASH_SHA256
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth = OAuth1RSA(consumer_key, signing_key)
header = {'Content-type' : 'application/json', 'Accept' : 'application/json'}

# Passing payload for data parameter as string
payload = '{"key" : "value"}'
request = requests.post(uri, data=payload, auth=oauth, headers=header)

# Passing payload for data parameter as Json object
payload = {'key' : 'value'}
request = requests.post(uri, data=json.dumps(payload), auth=oauth, headers=header)

# Passing payload for json parameter Json object
payload = {'key' : 'value'}
request = requests.post(uri, json=payload, auth=oauth, headers=header)
```

###### GET example

```python
from oauth1.oauth_ext import OAuth1RSA
import requests

uri = 'https://sandbox.api.mastercard.com/service'
oauth = OAuth1RSA(consumer_key, signing_key)

# Operation for get call
request = requests.get(uri, auth=oauth)
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
java -jar openapi-generator-cli.jar generate -i openapi-spec.yaml -g python -o out
```
See also:
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [CONFIG OPTIONS for python](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/python.md)

##### Usage of the `oauth1.signer_interceptor`

```python
import openapi_client
from oauth1.signer_interceptor import add_signer_layer

# ...
config = openapi_client.Configuration()
config.host = 'https://sandbox.api.mastercard.com'
client = openapi_client.ApiClient(config)
add_signer_layer(client, '<insert PKCS#12 key file path>', '<insert key password>', '<insert consumer key>')
some_api = openapi_client.SomeApi(client)
result = some_api.do_something()
# ...
```
