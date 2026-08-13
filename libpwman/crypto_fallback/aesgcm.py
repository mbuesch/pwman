"""
Fallback pure-Python AES-GCM (Galois/Counter Mode, NIST SP 800-38D) implementation.
NOTE: This implementation is USED ONLY IF Cryptodome is NOT used.

This file contains AI generated code and manually written code.

Copyright (c) 2026 Michael Büsch <m@bues.ch>
Licensed under the GNU/GPL version 2 or later.
"""

import hmac

class AESGCM:
    """AES in Galois/Counter Mode (AES-GCM)
    """

    __slots__ = (
        "__encrypt_block",
        "__h",
    )

    def __init__(self, encrypt_block):
        """Initialize AES-GCM with a block encryption function.
        `encrypt_block` must be a callable that takes a 16-byte block and returns the encrypted 16-byte block.
        """
        self.__encrypt_block = encrypt_block
        # H = CIPH_K(0^128) -- the hash subkey used throughout GHASH.
        self.__h = int.from_bytes(self.__encrypt_block(b"\x00" * 16), "big")

    # --------------------------------------------------------------------------
    # GF(2^128) arithmetic for GHASH
    # --------------------------------------------------------------------------
    # GCM works in the field GF(2^128) defined by the reduction polynomial
    #   f(x) = x^128 + x^7 + x^2 + x + 1
    # Blocks are interpreted as elements of this field using the "bit
    # reflected" convention from SP 800-38D, Section 6.3, where the most
    # significant bit of the first byte is the coefficient of x^0.
    #
    # The multiplication below follows the standard "shift-and-reduce"
    # algorithm (Algorithm 1 in SP 800-38D), operating on 128-bit integers
    # where bit 127 (MSB) corresponds to the polynomial's x^0 coefficient.

    @classmethod
    def __gf_mult(cls, x: int, y: int) -> int:
        """Multiply two 128-bit integers as elements of GCM's GF(2^128).
        """
        z = 0
        v = x
        R = 0xE1000000_00000000_00000000_00000000  # top byte 0xE1 followed by 120 zero bits
        for i in range(128):
            if (y >> (127 - i)) & 1:
                z ^= v
            # v = v * x  (multiply by the field's "x", i.e. a bit-shift + conditional reduce)
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v = v >> 1
        return z & 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF

    @classmethod
    def __ghash(cls, h: int, data: bytes) -> int:
        """GHASH_H(data), where `data` must be a multiple of 16 bytes.
        """
        assert len(data) % 16 == 0
        y = 0
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i:i + 16], "big")
            y = cls.__gf_mult(y ^ block, h)
        return y

    @classmethod
    def __pad16(cls, data: bytes) -> bytes:
        """Right-pad `data` with zero bytes up to the next multiple of 16.
        """
        rem = len(data) % 16
        if rem == 0:
            return data
        return data + b"\x00" * (16 - rem)

    def __inc32(self, block_int: int) -> int:
        """Increment the low 32 bits of a 128-bit block integer, mod 2^32.
        """
        high = block_int & 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000
        low = ((block_int & 0xFFFFFFFF) + 1) & 0xFFFFFFFF
        return high | low

    def __compute_j0(self, iv: bytes) -> int:
        """Derive the pre-counter block J0 from the IV (SP 800-38D, 7.1).
        """
        if len(iv) == 12:
            return (int.from_bytes(iv, "big") << 32) | 1
        # General case: J0 = GHASH_H( IV || 0^s || [len(IV)]_64 )
        s = (16 - (len(iv) % 16)) % 16
        padded = iv + (b"\x00" * s) + (b"\x00" * 8) + (len(iv) * 8).to_bytes(8, "big")
        return self.__ghash(self.__h, padded)

    def __gctr(self, icb_int: int, data: bytes) -> bytes:
        """GCTR_K: AES-CTR-style keystream XOR, starting at counter block icb_int.
        """
        if not data:
            return b""
        out = bytearray()
        counter = icb_int
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            ks = self.__encrypt_block(counter.to_bytes(16, "big"))
            out.extend(a ^ b for a, b in zip(chunk, ks))
            counter = self.__inc32(counter)
        return bytes(out)

    def __compute_tag(self, j0: int, aad: bytes, ciphertext: bytes) -> bytes:
        """Compute the authentication tag.
        """
        s_input = (
            self.__pad16(aad)
            + self.__pad16(ciphertext)
            + (len(aad) * 8).to_bytes(8, "big")
            + (len(ciphertext) * 8).to_bytes(8, "big")
        )
        s = self.__ghash(self.__h, s_input)
        return self.__gctr(j0, s.to_bytes(16, "big"))

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b""):
        """
        Encrypt with AES-GCM.

        nonce: 96 bit (12 byte) nonce, or bigger.
        plaintext: Data to encrypt.
        associated_data: Authenticated but not encrypted.

        Returns a tuple (ciphertext, authentication_tag).
        """
        if len(nonce) < 96 // 8:
            raise ValueError("nonce must be at least 96 bits")

        j0 = self.__compute_j0(nonce)
        ciphertext = self.__gctr(self.__inc32(j0), plaintext)
        tag = self.__compute_tag(j0, associated_data, ciphertext)
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, authentication_tag: bytes,
                associated_data: bytes = b""):
        """
        Decrypt and verify AES-GCM ciphertext and verify authenticated data.

        nonce: 96 bit (12 byte) nonce, or bigger.
        ciphertext: Data to decrypt.
        authentication_tag: Authentication tag to verify.
        associated_data: Authenticated but not encrypted.

        Raises ValueError if authentication fails (tag mismatch).
        """
        if len(nonce) < 96 // 8:
            raise ValueError("nonce must be at least 96 bits")
        if len(authentication_tag) != 16:
            raise ValueError("authentication_tag must be 16 bytes")

        j0 = self.__compute_j0(nonce)
        expected_tag = self.__compute_tag(j0, associated_data, ciphertext)

        if not hmac.compare_digest(expected_tag, authentication_tag):
            raise ValueError("AES-GCM authentication failed: tag mismatch")

        return self.__gctr(self.__inc32(j0), ciphertext)

    @classmethod
    def quickSelfTest(cls):
        import pyaes

        def new_aesgcm(key):
            aes = pyaes.AES(key)
            encrypt_block = lambda block: aes.encrypt(block)
            return AESGCM(encrypt_block)

        def hbytes(hexstr):
            return bytes.fromhex(hexstr)

        def check(cond, msg):
            if not cond:
                raise Exception("AES-GCM self-test failed: " + msg)

        # Test Case 1
        key = bytes(16)
        nonce = bytes(12)
        plaintext = b""
        aad = b""
        aesgcm = new_aesgcm(key)
        ciphertext, tag = aesgcm.encrypt(nonce, plaintext, aad)
        check(ciphertext == b"", "TC1: ciphertext")
        check(tag == hbytes("58e2fccefa7e3061367f1d57a4e7455a"), "TC1: tag")

        # Test Case 2
        key = bytes(16)
        nonce = bytes(12)
        plaintext = bytes(16)
        aesgcm = new_aesgcm(key)
        ciphertext, tag = aesgcm.encrypt(nonce, plaintext)
        check(ciphertext == hbytes("0388dace60b6a392f328c2b971b2fe78"), "TC2: ciphertext")
        check(tag == hbytes("ab6e47d42cec13bdf53a67b21257bddf"), "TC2: tag")
        check(aesgcm.decrypt(nonce, ciphertext, tag) == plaintext, "TC2: decryption")
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        try:
            aesgcm.decrypt(nonce, ciphertext, bad_tag)
            check(False, "TC2: expected authentication failure")
        except ValueError:
            pass

        # Test Case 3
        key = hbytes("feffe9928665731c6d6a8f9467308308")
        nonce = hbytes("cafebabefacedbaddecaf888")
        plaintext = hbytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        associated_data = hbytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        aesgcm = new_aesgcm(key)
        ciphertext, tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        check(ciphertext == hbytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"), "TC3: ciphertext")
        check(tag == hbytes("5bc94fbc3221a5db94fae95ae7121a47"), "TC3: tag")
        check(aesgcm.decrypt(nonce, ciphertext, tag, associated_data) == plaintext, "TC3: decryption")
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        try:
            aesgcm.decrypt(nonce, ciphertext, bad_tag, associated_data)
            check(False, "TC3: expected authentication failure")
        except ValueError:
            pass

if __name__ == "__main__":
    AESGCM.quickSelfTest()
    print("Self-tests passed.")
