import hashlib
from typing import List

def merkle_root(tx_hashes: List[bytes]) -> bytes:
    if not tx_hashes:
        return hashlib.sha256(b"").digest()
    current = [h for h in tx_hashes]
    while len(current) > 1:
        new_level = []
        # If odd -> duplicate the last element
        if len(current) % 2 == 1:
            current.append(current[-1])

        # Hash each pair
        for i in range(0, len(current), 2):
            combined = (current[i] + current[i+1])
            new_level.append(hashlib.sha256(combined).digest())
        current = new_level
    return current[0]