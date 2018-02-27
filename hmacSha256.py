
from hashlib import sha256

# ============================================================================
# ============================================================================
# ============================================================================

def HMACSha256(keyBin, msgBin) :

    block_size = 64 # SHA-256 blocks size
    
    trans_5C = bytearray(256)
    for x in range(len(trans_5C)) :
        trans_5C[x] = x^0x5C

    trans_36 = bytearray(256)
    for x in range(len(trans_36)) :
        trans_36[x] = x^0x36
    
    def translate(d, t) :
        res = bytearray(len(d))
        for x in range(len(d)) :
            res[x] = t[d[x]]
        return res
    
    keyBin = keyBin + chr(0) * (block_size - len(keyBin))
  
    inner = sha256()
    inner.update(translate(keyBin, trans_36))
    inner.update(msgBin)
    inner = inner.digest()
    
    outer = sha256()
    outer.update(translate(keyBin, trans_5C))
    outer.update(inner)
    
    return outer.digest()

# ============================================================================
# ============================================================================
# ============================================================================
