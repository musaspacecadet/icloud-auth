# iCloud [GSA-SRP] Authentication

This project implements the **Secure Remote Password (SRP)** authentication protocol for interacting with iCloud services using Apple's official endpoints. It includes password derivation and proof value generation to authenticate securely.

---

## Features

- **SRP Implementation**: Authentication logic for the Secure Remote Password protocol.
- **PBKDF2 Key Derivation**: Uses Apple's provided salt and iteration values to securely derive the password.
- **Endpoint Communication**: Interacts with Apple's APIs for login and authentication workflows.
- **Error Handling**: Detects and raises exceptions for failed login attempts or incomplete workflows.

---

## Project Structure

```plaintext
.
├── demo.cast             # Demo of the script in action (asciinema format)
├── demo.gif              # Animated demonstration of the script
├── libsrp.py             # SRP implementation for the authentication protocol
├── main.py               # Main script for performing authentication
├── primes.json           # JSON file with cryptographic primes used in SRP
├── requirements.txt      # Python dependencies
├── tests.py              # Unit tests for validating SRP logic
├── utils.py              # Utility functions for cryptographic operations
└── __pycache__/          # Cached Python bytecode files
```

---

## Demo

Here’s a quick preview of the script in action:

![Demo of SRP Authentication](demo.gif)

---

## Dependencies

### Required Libraries
- `requests`: For HTTP requests to Apple's API.
- `cryptography`: For PBKDF2-based password derivation.
- `base64`: Built-in Python library for Base64 encoding/decoding.

Install all dependencies using:
```bash
pip install -r requirements.txt
```

---

## Setup and Usage

1. **Run the Script**:
   Use the `main.py` script to authenticate with your Apple ID and password:
   ```bash
   python main.py
   ```

2. **Authentication Workflow**:
   - Initializes the SRP authentication with Apple's server.
   - Derives the password from the provided salt and iteration values.
   - Generates proof values (`m1` and `m2`) and completes login.

3. **Expected Responses**:
   - **HTTP 200**: Login successful.
   - **HTTP 409**: Multi-Factor Authentication (MFA) required (see the MFA section below).

---

## Authentication Workflow

1. **Client Ephemeral**:
   - Calculates the SRP public ephemeral value (`A`) and sends it to `/signin/init`.

2. **Server Response**:
   - Receives server ephemeral value (`B`), salt, and iteration count from Apple.

3. **Password Derivation**:
   - Uses PBKDF2 to securely derive a key based on the salt and iteration count.

4. **Proof Values**:
   - Generates `m1` and `m2` proof values for final authentication at `/signin/complete`.

---

## MFA Support (Future Work)

If the server responds with **HTTP 409**, MFA is required. Support for MFA can be added using the following endpoints in `ENDPOINTS`:

- **Trusted Device**:
  - Resend: `/verify/trusteddevice`
  - Enter Code: `/verify/trusteddevice/securitycode`
  
- **Phone Verification**:
  - Resend: `/verify/phone`
  - Enter Code: `/verify/phone/securitycode`

---

## Running Tests

To validate the SRP logic, run the `tests.py` script:
```bash
python tests.py
```

---

## Notes

1. **China-Specific Endpoint**:
   For accounts in China, update the base URL for setup to `icloud.com.cn`.

2. **Trust Token**:
   If you have a `trust_token`, pass it as an optional parameter to enhance authentication.

---

## Author

This project demonstrates iCloud SRP authentication. Contributions and feedback are welcome!
