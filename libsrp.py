from enum import Enum
import json
from typing import List, Tuple, Optional
from utils import (
    bigint_from_bytes,
    bytes_from_bigint,
    concat_bytes,
    constant_time_compare,
    from_hex,
    Hash,
    hash as hash_func,
    hash_interleave,
    mod_pow,
    random_bytes,
    to_hex,
    xor_bytes,
)

class PrimeField:
    def __init__(self, g: int, N: int, n: int):
        self.g = g
        self.N = N
        self.n = n

class Mode(Enum):
    RFC2945 = 0  # Implements the hash interleave
    SRPTools = 1
    GoSRP = 2
    GSA = 3


# Load the JSON data from the file
with open('primes.json', 'r') as f:
    prime_data = json.load(f)

# Known-safe prime fields from the loaded data
# Convert JSON data to known-safe prime fields
KNOWN_PRIME_FIELDS = {}
for key, value in prime_data.items():
    try:
        KNOWN_PRIME_FIELDS[int(key)] = PrimeField(
            value['g'],
            int(value['N'].strip(), 16),  # Strip whitespace and parse as hex
            value['n']
        )
    except ValueError as e:
        print(f"Error parsing key {key}: {e}")
        pass


 

def find_prime_field(bits: int = 0) -> PrimeField:
    """Find a known-safe prime field for a given number of bits."""
    if bits == 0:
        bits = 2048

    prime_field = KNOWN_PRIME_FIELDS.get(bits)

    if prime_field is None:
        raise ValueError(f"Invalid prime field size {bits}")

    return prime_field

def pad(x: int, n: int) -> bytes:
    """Returns a serialized bigint with padding to ensure it is at least n bytes."""
    b = bytes_from_bigint(x)
    if len(b) >= n:
        return b
    
    z = n - len(b)
    p = bytearray(n)
    for i in range(z):
        p[i] = 0
    p[z:] = b
    return bytes(p)

class Srp:
    def __init__(self, m: Mode, h:Hash, bits: int = 0):
        self.m = m
        self.h = h
        self.pf = find_prime_field(bits)

    def hash_int(self, buf: bytes) -> int:
        """Calculates the hash of a buffer and returns it as an integer."""
        return bigint_from_bytes(hash_func(self.h, buf))

    def verifier(self, I: bytes, p: bytes, salt: Optional[bytes] = None) -> 'Verifier':
        """Calculate a verifier for the given identity + passphrase."""
        ih = hash_func(self.h, I) if self.m == Mode.GoSRP else I
        ph = hash_func(self.h, p) if self.m == Mode.GoSRP else p
        
        if salt is None:
            salt = random_bytes(self.pf.n)

        if self.m == Mode.GoSRP:
            x = self.hash_int(concat_bytes(ih, ph, salt))
        else:
            x = self.hash_int(
                concat_bytes(
                    salt, 
                    hash_func(self.h, concat_bytes(ih, b'\x3A', ph))
                )
            )

        v = mod_pow(self.pf.g, x, self.pf.N)

        return Verifier(
            i=ih, 
            s=salt, 
            v=bytes_from_bigint(v), 
            h=self.h, 
            pf=self.pf
        )

    def new_client(self, I: bytes, p: bytes, a: Optional[int] = None) -> 'Client':
        """Initialize SRP client operations."""
        if a is None:
            a = bigint_from_bytes(random_bytes(self.pf.n))

        i = hash_func(self.h, I) if self.m == Mode.GoSRP else I
        p = hash_func(self.h, p) if self.m == Mode.GoSRP else p

        k = self.hash_int(
            concat_bytes(
                bytes_from_bigint(self.pf.N), 
                pad(self.pf.g, self.pf.n)
            )
        )

        return Client(
            s=self,
            i=i,
            p=p,
            a=a,
            A=mod_pow(self.pf.g, a, self.pf.N),
            k=k
        )

class Verifier:
    def __init__(self, i: bytes, s: bytes, v: bytes, h: Hash, pf: PrimeField):
        self.i = i
        self.s = s
        self.v = v
        self.h = h
        self.pf = pf

    def encode(self) -> Tuple[str, str]:
        """Encodes the verifier to a string."""
        ih = to_hex(self.i)
        b = ":".join([
            str(self.pf.n),
            hex(self.pf.N)[2:],
            hex(self.pf.g)[2:],
            str(self.h.value),  # Note: This might need adjustment based on how you handle hash functions
            ih,
            to_hex(self.s),
            to_hex(self.v)
        ])
        return ih, b

class Client:
    def __init__(self, s: Srp, i: bytes, p: bytes, a: int, A: int, k: int):
        self.s = s
        self.i = i
        self.p = p
        self.a = a
        self.A = A
        self.k = k
        self._K = b''
        self._M = b''

    @property
    def K(self):
        return self._K

    @property
    def M(self):
        return self._M

    def credentials(self) -> str:
        """Returns credentials to pass to the server."""
        return f"{to_hex(self.i)}:{to_hex(bytes_from_bigint(self.A))}"

    def parse_server_credentials(self, srv: str) -> Tuple[bytes, bytes]:
        """Parses serialized go-srp-style server credentials."""
        v = srv.split(":")
        if not v[0] or not v[1]:
            raise ValueError("Invalid server public key")

        salt = from_hex(v[0])
        B = from_hex(v[1])

        return salt, B

    def generate(self, salt: bytes, B: bytes) -> str:
        """Generates an authenticator, given server credentials."""
        Bn = bigint_from_bytes(B)
        
        if Bn % self.s.pf.N == 0:
            raise ValueError("Invalid server public key")

        u = self.s.hash_int(
            concat_bytes(
                pad(self.A, self.s.pf.n), 
                pad(Bn, self.s.pf.n)
            )
        )

        if u == 0:
            raise ValueError("Invalid server public key")

        if self.s.m == Mode.GoSRP:
            x = self.s.hash_int(concat_bytes(self.i, self.p, salt))
        else:
            x = self.s.hash_int(
                concat_bytes(
                    salt, 
                    hash_func(
                        self.s.h,
                        concat_bytes(
                            b'' if self.s.m == Mode.GSA else self.i, 
                            b'\x3A', 
                            self.p
                        )
                    )
                )
            )

        t0 = mod_pow(self.s.pf.g, x, self.s.pf.N) * self.k
        t1 = Bn - t0
        t2 = self.a + u * x
        S = mod_pow(t1, t2, self.s.pf.N)

        # SHA_Interleave is not used by most SRP implementations
        if self.s.m == Mode.RFC2945:
            self._K = hash_interleave(self.s.h, bytes_from_bigint(S))
        else:
            self._K = hash_func(self.s.h, bytes_from_bigint(S))

        if self.s.m == Mode.GoSRP:
            # Simplified construction used by Go SRP
            self._M = hash_func(
                self.s.h,
                concat_bytes(
                    self._K,
                    bytes_from_bigint(self.A),
                    bytes_from_bigint(Bn),
                    self.i,
                    salt,
                    bytes_from_bigint(self.s.pf.N),
                    bytes_from_bigint(self.s.pf.g)
                )
            )
        else:
            self._M = hash_func(
                self.s.h,
                concat_bytes(
                    xor_bytes(
                        hash_func(self.s.h, bytes_from_bigint(self.s.pf.N)),
                        hash_func(
                            self.s.h, 
                            pad(self.s.pf.g, self.s.pf.n) 
                            if self.s.m == Mode.GSA 
                            else bytes_from_bigint(self.s.pf.g)
                        )
                    ),
                    hash_func(self.s.h, self.i),
                    salt,
                    bytes_from_bigint(self.A),
                    bytes_from_bigint(Bn),
                    self._K
                )
            )

        return to_hex(self._M)

    def generate_m2(self) -> bytes:
        """Generate M2 used by GSA SRP."""
        if not self._M:
            raise ValueError("M not generated")
        
        M2 = hash_func(
            self.s.h,
            concat_bytes(
                bytes_from_bigint(self.A),
                self._M,
                self._K
            )
        )
        return M2

    def server_ok(self, proof: str) -> bool:
        """Validates the proof returned by the server."""
        h = hash_func(self.s.h, concat_bytes(self._K, self.M))
        return constant_time_compare(
            to_hex(h).encode(), 
            proof.encode()
        )