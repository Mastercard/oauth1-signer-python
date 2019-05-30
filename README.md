# oauth1-signer-python

[![](https://travis-ci.org/MastercardDevs/oauth1-signer-python.svg?branch=master)](https://travis-ci.org/MastercardDevs/oauth1-signer-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=MastercardDevs_oauth1-signer-python&metric=alert_status)](https://sonarcloud.io/dashboard?id=MastercardDevs_oauth1-signer-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=MastercardDevs_oauth1-signer-python&metric=coverage)](https://sonarcloud.io/dashboard?id=MastercardDevs_oauth1-signer-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=MastercardDevs_oauth1-signer-python&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=MastercardDevs_oauth1-signer-python)
[![](https://img.shields.io/pypi/v/mastercard-oauth1-signer.svg?style=flat&color=blue)](https://pypi.org/project/mastercard-oauth1-signer)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/MastercardDevs/oauth1-signer-python/blob/master/LICENSE)


## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Sample Code](#sample-code)
    * [Loading the Signing Key](#loading-the-signing-key)
    * [Creating the OAuth Authorization for a GET](#creating-the-oauth-get)
    * [Creating the OAuth Authorization for a POST](#creating-the-oauth-post)
    * [Complete code to use interceptors](#using-interceptors)



## Overview <a name="overview"></a>
This is the Python version of the Mastercard compliant OAuth signature libraries.

### Compatibility <a name="compatibility"></a>
Python 3.6, 3.7

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

#### PIP
`pip install mastercard-oauth1-signer`

#### or Clone 
`git clone https://github.com/Mastercard/oauth1-signer-python.git`

Change to the repo folder, and enter :

`python3 setup.py install`


### Sample Code <a name="sample-code"></a>

The following code snippets show how to use this signing library to send messages to a Mastercard service.


##### Imports needed for the code snippets.
``` python
import sys
import requests
from oauth1.oauth import OAuth
import oauth1.authenticationutils as authenticationutils
import json
from urllib.parse import urlencode
```

##### Get a signing key from the .p12 file (replace place-holder strings with values from your project in developer zone). <a name="loading-the-signing-key"></a>
``` python
signing_key = authenticationutils.load_signing_key('your-keyFile.p12', 'the-keystore-password')
consumer_key = 'your-consumer-key-from-developer.mastercard.com'

baseUrl = 'https://sandbox.api.mastercard.com' # remove 'sandbox.' if calling production
```


##### To send a GET with query parameters:  <a name="creating-the-oauth-get"></a>

``` python
queryMap = {
        "Format": "XML",    # change this to toggle between and XML or JSON response
        "Details": "offers.easysavings",
        "PageOffset": "0",
        "PageLength": "5",
        "Latitude": "38.53463",
        "Longitude": "-90.286781"
        }
uri = baseUrl + "/merchants/v1/merchant?" + urlencode(queryMap)
header = OAuth().get_authorization_header(uri, 'GET', None, consumer_key, signing_key)
headers = {'Authorization': header, 'Content-Type': 'application/json'}

r = requests.get(uri, headers=headers)
print(r.text)

```


##### To send a POST to : <a name="creating-the-oauth-post"></a>

``` python
uri = baseUrl + "/eop/offer/v1/search?Format=XML" # change this to toggle between and XML or JSON response
reqBodyMap = {
        'OfferSearchCriteria': {
                'ItemsPerPage': 300,
                'Program': 'easysavings'
        }
}
reqJson = json.dumps(reqBodyMap)
header = OAuth().get_authorization_header(uri, 'POST', reqJson, consumer_key, signing_key)
headers = {'Authorization': header, 'Content-Type': 'application/json'}
r = requests.post(uri, headers=headers, data=reqJson)
print(r.text)
```



##### Complete snippet to use interceptors : <a name="using-interceptors"></a>

``` python
            signing_key = authenticationutils.load_signing_key('your-keyFile.p12', 'the-keystore-password')
            consumer_key = 'your-consumer-key-from-developer.mastercard.com'

            baseUrl = 'https://sandbox.api.mastercard.com'

            service_cli = APIClientYourService()
            add_signing_layer(self, service_cli, key_file, key_password, consumer_key)

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

```
