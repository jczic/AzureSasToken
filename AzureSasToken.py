"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""

from binascii   import a2b_base64, b2a_base64
from time       import time
from hmacSha256 import HMACSha256

# ============================================================================
# ============================================================================
# ============================================================================

def GenerateAzureSasToken(uri, key, expiryTimestamp, policy_name=None) :

    def _quote(s) :
        r = ''
        for c in str(s) :
            if (c >= 'a' and c <= 'z') or \
               (c >= '0' and c <= '9') or \
               (c >= 'A' and c <= 'Z') or \
               (c in '.-_') :
                r += c
            else :
                r += '%%%02X' % ord(c)
        return r

    uri       = _quote(uri)
    sign_key  = b'%s\n%d' % (uri, int(expiryTimestamp))
    key       = a2b_base64(key)
    hmac      = HMACSha256(key, sign_key)
    signature = _quote( b2a_base64(hmac).decode().strip() )

    token = 'sr='  + uri       + '&' + \
            'sig=' + signature + '&' + \
            'se='  + str(expiryTimestamp)
    if policy_name :
        token += '&' + 'skn=' + policy_name

    return 'SharedAccessSignature ' + token

# ============================================================================
# ============================================================================
# ============================================================================

