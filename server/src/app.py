import argparse
import josepy as jose
import OpenSSL
import os
import json
import time
import datetime

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Parse command-line arguments
parser = argparse.ArgumentParser(description="ACME client for DNS-01 challenge")
parser.add_argument("-e", "--email", type=str, help="Contact email for ACME registration", required=True)
parser.add_argument("-d", "--domain", action="append", type=str, required=True, help="Domain name(s)")
parser.add_argument("--csr", type=str, help="Path to an existing CSR file (optional)")
parser.add_argument("--domain_key", type=str, help="Path to an existing domain key file (optional)")
parser.add_argument('--time_it', action='store_true', help="Enable timing of operations")
args = parser.parse_args()
if len(str(args.domain)) < 250:
    out_name = str(args.domain)
else:
    out_name = str(args.domain)[:250]

if not os.path.exists('./dat'):
    os.mkdir('./dat')

# default
acc_key_path = "./dat/account_key.pem"
regr_file_path = "./dat/account_regr.json"

DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

USER_AGENT = 'python-acme-example'

# Useful methods and classes:
def load_or_generate_acc_key(file_path):
    if file_path and os.path.exists(file_path):
        with open(file_path, 'rb') as key_file:
            private_key =  serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    else:
        # Generate a new RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=ACC_KEY_BITS,  # Ensure ACC_KEY_BITS is defined
            backend=default_backend()
        )

        # Serialize the private key to PEM format
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Write the PEM-encoded private key to a file
        with open(acc_key_path, 'wb') as acc_key_file:
            acc_key_file.write(pem)
        # After saving the PEM, convert the private key to a JWKRSA object for ACME operations

    return jose.JWKRSA(key=private_key)

def csr_comp(domain_name, pkey_path=None, csr_path=None):
    """Load/Create/Dump certificate signing request."""
    if pkey_path and os.path.exists(pkey_path):
        with open(pkey_path, 'rb') as key_file:
            pkey_pem = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        # Serialize the private key back to PEM format
        pkey_pem = pkey_pem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    if csr_path and os.path.exists(csr_path):
        with open(csr_path, 'rb') as csr_file:
            csr_pem = x509.load_pem_x509_csr(
                csr_file.read(),
                backend=default_backend()
            ).public_bytes(serialization.Encoding.PEM)
    else:
        csr_pem = crypto_util.make_csr(pkey_pem, domain_name)

    return pkey_pem, csr_pem


def select_dns01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations
    DNS_challenges = {}

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        print(authz.body.identifier.typ)
        print(authz.body.identifier.value)
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                DNS_challenges[authz.body.identifier.value] = i

    if len(DNS_challenges) > 0:
        return DNS_challenges
    raise Exception('DNS-01 challenge was not offered by the CA server.')


def main():
    if args.csr and not os.path.exists(args.csr):
        print("invalid csr path") 
        exit(1)
    if args.domain_key and not os.path.exists(args.domain_key):
        print("invalid domain_key path") 
        exit(1)
    
    # timer start
    timing_info = {}

    def mark_time(event_name, point):
        if args.time_it:
            if event_name not in timing_info:
                timing_info[event_name] = {}
            timing_info[event_name][point] = time.perf_counter()
    
    mark_time('key_csr_gen', 'start')
    pkey_pem, csr_pem = csr_comp(args.domain, args.domain_key, args.csr)
    mark_time('key_csr_gen', 'end')

    # Check if a new private key was generated and needs to be saved
    if not args.domain_key or not os.path.exists(args.domain_key):
        pkey_path = f"./dat/{out_name}.key"  # Default path for saving the private key
        with open(pkey_path, 'wb') as key_file:
            key_file.write(pkey_pem)

    # Check if a new CSR was generated and needs to be saved
    if not args.csr or not os.path.exists(args.csr):
        csr_path = f"./dat/{out_name}.csr"  # Default path for saving the private csr
        with open(csr_path, 'wb') as csr_file:
            csr_file.write(csr_pem)

    acc_key = load_or_generate_acc_key(acc_key_path)
    if os.path.exists(acc_key_path) and os.path.exists(regr_file_path):
        with open(regr_file_path, 'rb') as regr_file:
            acc_regr = json.load(regr_file)
        mark_time('acme_connect', 'start')
        net = client.ClientNetwork(acc_key, account=acc_regr, user_agent=USER_AGENT)
    # connect server
    else:
        mark_time('acc_regr', 'start')
        net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
    client_acme = client.ClientV2(directory, net=net)

    if not os.path.exists(regr_file_path):
        # Register account and accept TOS
        email = (args.email)
        regr = client_acme.new_account(
            messages.NewRegistration.from_data(
                email=email, terms_of_service_agreed=True))
        mark_time('acc_regr', 'end')
        regr_data = {
            'uri': regr.uri,  # The account URI, acting as Key ID in ACME v2
            'terms_of_service': getattr(regr, 'terms_of_service', None)
        }
        with open(regr_file_path, 'w') as regr_file:
            json.dump(regr_data, regr_file)
    else:
        mark_time('acme_connect', 'end')

    mark_time('order_req', 'start')
    # Issue certificate
    orderr = client_acme.new_order(csr_pem)

    # Select DNS-01 within offered challenges by the CA server
    challbs = select_dns01_chall(orderr)
    # {domain: challb, ...}
    mark_time('order_req', 'end')
    challb_responses = []

    for domain, challb in challbs.items():
        # Perform DNS-01 challenge.
        response, validation = challb.response_and_validation(client_acme.net.key)
        dns_record_name = "_acme-challenge." + domain
        if not dns_record_name.endswith("."):
          dns_record_name += "."
        print(f"Please create a DNS TXT record in your zone:")
        print(f"{dns_record_name}\tIN\tTXT\t\"{validation}\"")
        challb_responses.append((challb, response))

    mark_time('dns_prop', 'start')
    # Wait for challenge status and then issue a certificate.
    # It is possible to set a deadline time.
    input("Press Enter after you have added the DNS record and it has propagated...")
    mark_time('dns_prop', 'end')


    mark_time('ans_chal', 'start')
    for (challb, response) in challb_responses:
        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)
    mark_time('ans_chal', 'end')

    mark_time('order_comp', 'start')
    try:
        finalized_orderr = client_acme.poll_and_finalize(orderr)
    except:
        print("Validation failed, try again")
        exit(1)
    mark_time('order_comp', 'end')

    fullchain_pem = finalized_orderr.fullchain_pem
    fullchain_path = f"./dat/{out_name}.crt"  # Default path for saving the private crt
    with open(fullchain_path, 'w') as fullchain_file:
        fullchain_file.write(fullchain_pem)

    if args.time_it:
        with open(f"./dat/{datetime.datetime.now().strftime('%Y%m%d%H%M%S')+out_name}.dat", "w") as f:
            f.write(f"{out_name}\n")
            for e, t in timing_info.items():
                f.write(f"{e} took {t['end']-t['start']} seconds\n")

if __name__ == "__main__":
    main()
