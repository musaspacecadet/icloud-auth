import requests
import base64
from libsrp import Srp, Mode, Client
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from utils import (
    bytes_from_bigint,
    Hash,
    hash as hash_func,
    to_hex,
)
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/javascript, */*; q=0.01",
}


ENDPOINTS = {
        "AUTH": {
            "BASE": "https://idmsa.apple.com/appleauth/auth",
            "PATH": {
                "SIGNIN": {
                    "LEGACY": "/signin",
                    "INIT": "/signin/init",
                    "COMPLETE": "/signin/complete"
                },
                "MFA": {
                    "DEVICE_RESEND": "/verify/trusteddevice",
                    "DEVICE_ENTER": "/verify/trusteddevice/securitycode",
                    "PHONE_RESEND": "/verify/phone",
                    "PHONE_ENTER": "/verify/phone/securitycode",
                },
                "TRUST": "/2sv/trust",
            },
        },
        "SETUP": {
            "BASE": "https://setup.icloud.com", # china uses icloud.com.cn
            "PATH": {
                "ACCOUNT_LOGIN": "/setup/ws/1/accountLogin",
                "REQUEST_PCS": "/setup/ws/1/requestPCS",
            },
        },
        "PHOTOS": {
            "BASE_PATH": "/database/1/com.apple.photos.cloud/production/private",
            "PATH": {
                "QUERY": "/records/query",
                "MODIFY": "/records/modify",
                "ZONES": "/changes/database",
            },
        },
    }

class iCloudCrypto:
    def __init__(self,username: str,password :str):
        # Initialize the SRP client with 2048-bit modulus and SHA-256 hashing
        self.username=username
        self.password=password
        self.srp = Srp(Mode.GSA, Hash.SHA256, 2048)
        self.srp_client : Client = self.srp.new_client(I=bytes(username,encoding='utf-8'),p=bytes("",encoding='utf-8')) 

        print(f"username {self.username} : password = {self.password}")

    def get_client_ephemeral(self):
        """
        Returns the client's ephemeral value (public key 'A') as a base64 string.
        """
        
        return base64.b64encode(bytes_from_bigint(self.srp_client.A)).decode('utf-8')#.to_bytes(256, byteorder='big')

    def derive_password(self, protocol, salt, iterations):
        """
        Derives the password key using PBKDF2 based on the provided protocol, salt, and iterations.
        """
        pass_hash = hash_func(self.srp.h, self.password.encode())

        if protocol == 's2k_fo':
            pass_hash = to_hex(pass_hash)

        salt_bytes = base64.b64decode(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=iterations,
            backend=default_backend()
        )
        derived_key = kdf.derive(pass_hash)
        return derived_key

    def get_proof_values(self, derived_password, server_public_value, salt):
        """
        Generates proof values required for authentication.
        """
        salt_bytes = base64.b64decode(salt)
        server_public_value_bytes = base64.b64decode(server_public_value)

        # Perform SRP calculations to get the M1 and M2 proof values
        self.srp_client.p = derived_password
    
        M1 = bytes.fromhex(self.srp_client.generate(salt_bytes, server_public_value_bytes))
        
        # Generate the Host Authentication Message (HAMK)
        M2 = self.srp_client.generate_m2()

        # Convert proof values to base64
        m1_base64 = base64.b64encode(M1).decode('utf-8')
        m2_base64 = base64.b64encode(M2).decode('utf-8')

        return m1_base64, m2_base64

class iCloudCryptoAuth:
    def get_SRP_login(self, username, password ,trust_token=[]):
        """
        Generates the SRP login payload and URL from the iCloud server challenge.
        """
        
        authenticator = iCloudCrypto(username=username,password=password)
        
        print("Generating SRP challenge")

        try:
            # Initialize SRP login with client ephemeral value
            init_response = requests.post(
                ENDPOINTS["AUTH"]["BASE"] + ENDPOINTS["AUTH"]["PATH"]["SIGNIN"]["INIT"],
                headers=headers,
                json={
                    "a": authenticator.get_client_ephemeral(),
                    "accountName": username,
                    "protocols": ["s2k", "s2k_fo"],
                },
            )
            
            # Parse response
            print(init_response.content)
            init_data = init_response.json()

            # Derive password using provided salt, protocol, and iteration count
            derived_password = authenticator.derive_password(
                init_data["protocol"],
                init_data["salt"],
                init_data["iteration"]
            )

            # Generate proof values (m1 and m2) for SRP authentication
            m1_proof, m2_proof = authenticator.get_proof_values(
                derived_password,
                init_data["b"],
                init_data["salt"]
            )

            # Prepare final payload
            payload = {
                "accountName": username,
                "trustTokens": trust_token,
                'rememberMe': True,
                "m1": m1_proof,
                "m2": m2_proof,
                "c": init_data["c"],
            }
            
            return (
                ENDPOINTS["AUTH"]["BASE"] + ENDPOINTS["AUTH"]["PATH"]["SIGNIN"]["COMPLETE"],
                payload
            )
            
        except Exception as err:
            # Handle any errors that occurred during SRP initialization
            raise Exception("SRP initialization failed") from err


auth = iCloudCryptoAuth()
url, payload = auth.get_SRP_login(username="freelancewritermusa@gmail.com",password="/i9AFWtrkyP-b3x")
params = {
    'isRememberMeEnabled': 'true',
}

print(payload)

response = requests.post(
    url,
    params=params,
    headers=headers,
    json=payload,
)
## if response is 409 , MFA is needed but not implemented yet. 200 is ok
print(response.headers)
print(response.content)