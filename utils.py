import hashlib
import os


def bit_length(n: int) -> int:
    """
    Returns the length of the bigint in bits.
    
    :param n: bigint to check
    :return: count of bits needed to store bigint
    """
    return n.bit_length()


def byte_length(n: int) -> int:
    """
    Returns the length of the bigint in bytes. Rounds up to the nearest byte.
    
    :param n: bigint to check
    :return: count of bytes needed to store bigint
    """
    return (bit_length(n) + 7) // 8


def bigint_from_bytes(buf: bytes) -> int:
    """
    Deserializes a buffer of bytes into a bigint.
    
    :param buf: buffer containing a serialized bigint
    :return: deserialized value parsed from buf
    """
    return int.from_bytes(buf, byteorder='big')


def bytes_from_bigint(v: int) -> bytes:
    """
    Serializes a bigint into a buffer of bytes.
    
    :param v: value to serialize
    :return: serialized form of v
    """
    return v.to_bytes(byte_length(v), byteorder='big')


def random_bytes(num_bytes: int) -> bytes:
    """
    Returns cryptographically-safe random bytes into a buffer.
    
    :param num_bytes: number of bytes
    :return: buffer containing random bytes
    """
    if num_bytes < 1:
        raise ValueError("numBytes must be >= 1")
    return os.urandom(num_bytes)


def to_zn(a: int, n: int) -> int:
    """
    Returns the smallest positive value in the multiplicative group of integers modulo n that is congruent to a.
    
    :param a: value to find congruent value of
    :param n: modulo of multiplicative group
    :return: smallest positive congruent value of a in integers modulo n
    """
    if n < 1:
        raise ValueError("n must be > 0")
    return a % n if a % n >= 0 else a % n + n


def e_gcd(a: int, b: int) -> dict:
    """
    Solves for values g, x, y, such that g = gcd(a, b) and g = ax + by.
    
    :param a: first value
    :param b: second value
    :return: dictionary with g, x, and y
    """
    if a < 1 or b < 1:
        raise ValueError("a and b must be > 0")

    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a = a, r
        x, y = u, v
        u, v = m, n

    return {"g": b, "x": x, "y": y}


def mod_inv(a: int, n: int) -> int:
    """
    Calculates the modular inverse of a in the multiplicative group of integers modulo n.
    
    :param a: value to calculate inverse for
    :param n: modulo
    :return: modular inverse of a modulo n
    """
    egcd = e_gcd(to_zn(a, n), n)
    if egcd["g"] != 1:
        raise ValueError("No modular inverse")
    return to_zn(egcd["x"], n)


def mod_pow(x: int, y: int, m: int) -> int:
    """
    Calculates the value of x ^ y % m efficiently.
    
    :param x: base
    :param y: exponent
    :param m: modulus
    :return: result of (x ^ y) % m
    """
    if m < 1:
        raise ValueError("m must be > 0")
    elif m == 1:
        return 0

    x = to_zn(x, m)

    if y < 0:
        return mod_inv(mod_pow(x, abs(y), m), m)

    r = 1
    while y > 0:
        if y % 2 == 1:
            r = (r * x) % m
        y //= 2
        x = (x * x) % m

    return r


def concat_bytes(*a: bytes) -> bytes:
    """
    Concatenates multiple buffers into one new buffer.
    
    :param a: buffers to concatenate
    :return: new buffer containing the concatenated contents
    """
    return b''.join(a)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XORs two equal-size byte arrays together.
    
    :param a: first buffer to XOR
    :param b: second buffer to XOR
    :return: XORed buffer
    """
    if len(a) != len(b):
        raise ValueError("Buffers must be the same length")
    return bytes([x ^ y for x, y in zip(a, b)])


def to_hex(buffer: bytes) -> str:
    """
    Encodes a buffer into a hexadecimal string.
    
    :param buffer: buffer to encode
    :return: hex-encoded form of buffer
    """
    return buffer.hex()


def from_hex(hex_str: str) -> bytes:
    """
    Decodes a hexadecimal string into a new buffer.
    
    :param hex_str: hexadecimal string to decode
    :return: buffer of bytes decoded from hex_str
    """
    return bytes.fromhex(hex_str)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compares two buffers with constant-time execution.
    
    :param a: first buffer to compare
    :param b: second buffer to compare
    :return: True if a == b, otherwise False
    """
    if len(a) != len(b):
        return False
    return all(x == y for x, y in zip(a, b))


class Hash:
    SHA1 = 3
    SHA256 = 5
    SHA384 = 6
    SHA512 = 7


def hash(hash_type: int, data: bytes) -> bytes:
    """
    Returns the result of applying a hash to the given buffer.
    
    :param hash_type: hash algorithm to use
    :param data: data to hash
    :return: digest
    """
    if hash_type == Hash.SHA1:
        return hashlib.sha1(data).digest()
    elif hash_type == Hash.SHA256:
        return hashlib.sha256(data).digest()
    elif hash_type == Hash.SHA384:
        return hashlib.sha384(data).digest()
    elif hash_type == Hash.SHA512:
        return hashlib.sha512(data).digest()
    else:
        raise ValueError("Unsupported hash type")


def hash_interleave(h: int, data: bytes) -> bytes:
    """
    Hashes data by interleaving even and odd byte positions.
    
    :param h: hash type
    :param data: data to hash
    :return: interleaved hash result
    """
    copy = bytearray(data)
    for i in range(len(copy)):
        if copy[i] != 0:
            if (len(copy) - i) % 2 == 1:
                i += 1
            copy = copy[i:]
            break

    halfl = len(copy) // 2
    even = bytearray(halfl)
    odd = bytearray(halfl)
    for i in range(halfl):
        even[i] = copy[i * 2]
        odd[i] = copy[i * 2 + 1]

    hash1 = hash(h, bytes(even))
    hash2 = hash(h, bytes(odd))

    result = bytearray(len(hash1) * 2)
    for i in range(len(hash1)):
        result[i * 2] = hash1[i]
        result[i * 2 + 1] = hash2[i]

    return bytes(result)
