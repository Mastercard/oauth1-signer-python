import json
from base64 import b64decode
from urllib.parse import unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from oauth1 import coreutils as util
from oauth1.oauth import OAuth, SignatureMethod


def extract_oauth_params(header):
    params = {}
    header_value = header[6:] if header.startswith('OAuth ') else header
    for item in header_value.split(','):
        key, value = item.split('=', 1)
        params[key] = value.strip('"')
    return params


def expected_body_hash(payload):
    payload_value = json.dumps(payload) if type(payload) is dict or type(payload) is list else payload
    if not payload_value:
        payload_value = OAuth.EMPTY_STRING
    return util.base64_encode(util.sha256_encode(payload_value))

# These assertions exercise the real signing path end to end: reconstruct the
# OAuth base string from the emitted header and verify the signature with the
# public key using the expected padding scheme for the selected method.
def assert_oauth_header_is_valid(test_case, uri, method, payload, header, public_key,
                                 expected_consumer_key, expected_nonce, expected_timestamp,
                                 expected_signature_method, signature_method):
    params = extract_oauth_params(header)

    test_case.assertEqual(expected_consumer_key, params['oauth_consumer_key'])
    test_case.assertEqual(expected_nonce, params['oauth_nonce'])
    test_case.assertEqual(str(expected_timestamp), params['oauth_timestamp'])
    test_case.assertEqual(expected_signature_method, params['oauth_signature_method'])
    test_case.assertEqual('1.0', params['oauth_version'])
    test_case.assertEqual(expected_body_hash(payload), params['oauth_body_hash'])

    base_params = dict(params)
    signature = b64decode(unquote(base_params.pop('oauth_signature')))
    base_string = OAuth.get_base_string(uri, method, base_params)

    if signature_method is SignatureMethod.RSA_PSS_SHA256:
        padding_scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    else:
        padding_scheme = padding.PKCS1v15()

    public_key.verify(signature, base_string.encode('utf-8'), padding_scheme, hashes.SHA256())

    return params