# oauth1-signer-python

[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/oauth1-signer-java/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Sample Code](#sample-code)
    * [Breakdown of the Sample](#sample-breakdown)
      * [Loading the Signing Key](#loading-the-signing-key)
      * [Creating the OAuth Authorization for a GET](#creating-the-oauth-get)
      * [Creating the OAuth Authorization for a POST](#creating-the-oauth-post)



## Overview <a name="overview"></a>
This is an alpha version of the Pyhon library for generating a Mastercard API compliant OAuth signature.
As such it is a work-in-progress, not for commercial use, and unsupported. This warning will be removed when the bundle is finalised.

### Compatibility <a name="compatibility"></a>
Python 3.7.x

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
`pip3 install git+https://github.com/Mastercard/oauth1-signer-python.git`

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
consumer_key = 'your-consumer-key-from-devzone'

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


