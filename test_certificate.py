import os
import base64
import uuid
import requests
import subprocess
import tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

load_dotenv()

ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
ORG = os.getenv('ORG')
ENV = os.getenv('ENV')
BASE_URL = os.getenv('BASE_URL')

CERT_TYPE = 'WRPAC'
CERT = (f'certs/{ORG}/{ENV}/transport.pem', f'certs/{ORG}/{ENV}/transport.key')
HEADERS = {'Authorization': f'Bearer {ACCESS_TOKEN}'}

BASE_CNF = """[req]
default_bits = 2048
default_md = sha256
encrypt_key = yes
prompt = no
string_mask = nombstr
distinguished_name = client_distinguished_name
req_extensions = req_cert_extensions

[ client_distinguished_name ]
countryName = BR
organizationName = Cypress Org Own
organizationIdentifier = VATBR-889333566138222
organizationalUnitName = {ou_placeholder}
commonName = Cypress_03_09_2025_1f333acfe

[ req_cert_extensions ]
subjectAltName = @alt_name

[ alt_name ]
URI.1 = www.testing.com
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def api_post(path, payload=None, data=None, content_type='application/json'):
    headers = {**HEADERS, 'Content-Type': content_type}
    return requests.post(
        f'{BASE_URL}{path}',
        json=payload,
        data=data,
        headers=headers,
        cert=CERT,
        verify=False
    )


def api_get(path):
    return requests.get(f'{BASE_URL}{path}', headers=HEADERS, cert=CERT, verify=False)


def generate_csr(cnf_content, key_size=2048, extra_args=None):
    with tempfile.TemporaryDirectory() as tmpdir:
        cnf_path = os.path.join(tmpdir, 'csr.cnf')
        key_path = os.path.join(tmpdir, 'csr.key')
        csr_path = os.path.join(tmpdir, 'csr.pem')

        with open(cnf_path, 'w') as f:
            f.write(cnf_content)

        cmd = ['openssl', 'req', '-new', '-utf8', '-newkey', f'rsa:{key_size}',
               '-nodes', '-out', csr_path, '-keyout', key_path, '-config', cnf_path]
        if extra_args:
            cmd += extra_args

        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode())

        with open(csr_path, 'r') as f:
            return f.read()


def extract_cert_pem(response):
    content_type = response.headers.get('Content-Type', '')
    if 'pem' in content_type or response.text.strip().startswith('-----BEGIN'):
        return response.text
    x5c = response.json().get('x5c')
    if x5c:
        der = base64.b64decode(x5c[0])
        return (
            '-----BEGIN CERTIFICATE-----\n' +
            base64.b64encode(der).decode('utf-8') + '\n' +
            '-----END CERTIFICATE-----\n'
        )
    return None


def verify_certificate(cert_pem, expect_ou=True):
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    subject = cert.subject
    results = []

    def check(name, passed, detail=''):
        status = '✅ Pass' if passed else '❌ Fail'
        print(f'    {name}: {status}' + (f' — {detail}' if detail else ''))
        results.append(passed)

    cn = next((a.value for a in subject if a.oid.dotted_string == '2.5.4.3'), None)
    o = next((a.value for a in subject if a.oid.dotted_string == '2.5.4.10'), None)
    ou = next((a.value for a in subject if a.oid.dotted_string == '2.5.4.11'), None)
    org_identifier = next((a.value for a in subject if a.oid.dotted_string == '2.5.4.97'), None)

    check('Subject contains CN=', cn is not None, cn or '')
    check('Subject contains O=', o is not None, o or '')
    check('Subject contains organizationIdentifier=', org_identifier is not None, org_identifier or '')
    if expect_ou:
        check('OU provided → OU present in certificate', ou is not None, ou or '')
    else:
        check('OU not provided → OU absent in certificate', ou is None)

    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ''
    check('Signature Algorithm = SHA-256', sig_alg == 'sha256', sig_alg)

    pub_key = cert.public_key()
    pub_key_type = type(pub_key).__name__
    check('Public Key = RSA or ECDSA', 'RSA' in pub_key_type or 'EC' in pub_key_type, pub_key_type)
    if hasattr(pub_key, 'key_size'):
        check('Public Key >= 2048 bits', pub_key.key_size >= 2048, f'{pub_key.key_size}-bit')

    issuer_str = cert.issuer.rfc4514_string()
    check('Issuer contains Raidiam CA name', 'raidiam' in issuer_str.lower(), issuer_str)
    check('Not self-signed', cert.issuer != cert.subject)

    return all(results)


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup():
    print('\n══════════════════════════════════════')
    print('  SETUP')
    print('══════════════════════════════════════')

    authority_id, authority_name, domain_name, role_name = _fetch_authority_domain()
    org_id = _create_organisation()
    _create_authority_domain_claim(org_id, authority_id, authority_name, domain_name)
    _create_authority_claim(org_id, authority_id, domain_name, role_name)
    ss_id = _create_software_statement(org_id, domain_name, role_name)

    return org_id, ss_id


def _fetch_authority_domain():
    r = api_get('/references/authorityauthorisationdomains')
    if r.status_code != 200:
        raise RuntimeError(f'Failed to fetch authority domains [{r.status_code}]: {r.text}')

    items = r.json()
    if isinstance(items, dict):
        items = items.get('content', items.get('Data', []))
    if not items:
        raise RuntimeError('No authority-domain mappings found in this environment')

    entry = items[0]
    authority_id = entry.get('AuthorityID') or entry.get('AuthorityId')
    authority_name = entry.get('AuthorityName')
    domain_name = entry.get('AuthorisationDomainName')

    r2 = api_get(f'/references/authorisationdomains/{domain_name}/authorisationdomainroles')
    if r2.status_code != 200:
        raise RuntimeError(f'Failed to fetch domain roles [{r2.status_code}]: {r2.text}')

    roles = r2.json()
    if isinstance(roles, dict):
        roles = roles.get('content', roles.get('Data', []))
    active_roles = [r for r in roles if r.get('Status') == 'Active']
    if not active_roles:
        raise RuntimeError(f'No active roles found for domain {domain_name}')

    role_name = active_roles[0].get('AuthorisationDomainRoleName')
    print(f'  ℹ️  Using authority={authority_name} ({authority_id}), domain={domain_name}, role={role_name}')
    return authority_id, authority_name, domain_name, role_name


def _create_organisation():
    org_id = str(uuid.uuid4())
    org_name = f'CertAutoTest Org {org_id[:8]}'
    response = api_post('/organisations/', {
        'OrganisationId': org_id,
        'OrganisationName': org_name,
        'Status': 'Active',
        'CountryOfRegistration': 'BR',
        'RegistrationNumber': '889333566138222',
        'LegalEntityName': 'Cypress Org Own',
        'AddressLine1': 'test line 1',
        'City': 'London',
        'Postcode': 'ME19 5FG',
        'Country': 'BR',
        'CompanyRegister': 'REG123',
    })
    if response.status_code != 201:
        raise RuntimeError(f'Failed to create organisation [{response.status_code}]: {response.text}')
    print(f'  ✅ Organisation created: {org_name} ({org_id})')
    return org_id


def _create_authority_domain_claim(org_id, authority_id, authority_name, domain_name):
    response = api_post(f'/organisations/{org_id}/authoritydomainclaims', {
        'AuthorisationDomainName': domain_name,
        'AuthorityId': authority_id,
        'AuthorityName': authority_name,
    })
    if response.status_code != 201:
        raise RuntimeError(f'Failed to create authority domain claim [{response.status_code}]: {response.text}')
    print(f'  ✅ Authority domain claim created')


def _create_authority_claim(org_id, authority_id, domain_name, role_name):
    response = api_post(f'/organisations/{org_id}/authorityclaims', {
        'AuthorityId': authority_id,
        'Status': 'Active',
        'AuthorisationDomain': domain_name,
        'Role': role_name,
        'RegistrationId': 'REG123',
    })
    if response.status_code != 201:
        raise RuntimeError(f'Failed to create authority claim [{response.status_code}]: {response.text}')
    print(f'  ✅ Authority claim created')


def _create_software_statement(org_id, domain_name, role_name):
    ss_name = f'CertAutoTest SS {str(uuid.uuid4())[:8]}'
    response = api_post(f'/organisations/{org_id}/softwarestatements', {
        'ClientName': ss_name,
        'Description': 'Created by cert auto-test script',
        'LogoUri': 'https://www.example.com/file.svg',
        'RedirectUri': ['https://www.example.com/file.svg'],
        'Version': 40,
        'ClientUri': 'https://www.example.com',
        'Roles': [{'Status': 'Active', 'AuthorisationDomain': domain_name, 'Role': role_name}],
    })
    if response.status_code != 201:
        raise RuntimeError(f'Failed to create software statement [{response.status_code}]: {response.text}')
    ss_id = response.json().get('SoftwareStatementId')
    print(f'  ✅ Software Statement created: {ss_name} ({ss_id})')
    return ss_id


# ── Tests ─────────────────────────────────────────────────────────────────────

def run_positive_tests(org_id, ss_id):
    print('\n══════════════════════════════════════')
    print('  POSITIVE TESTS')
    print('══════════════════════════════════════')

    cnf_with_ou = BASE_CNF.replace('{ou_placeholder}', ss_id)
    cnf_without_ou = BASE_CNF.replace('organizationalUnitName = {ou_placeholder}\n', '')

    summary = []
    summary.append(_positive('P1: Valid CSR with OU', org_id, ss_id, cnf_with_ou, expect_ou=True))
    summary.append(_positive('P2: Valid CSR without OU', org_id, ss_id, cnf_without_ou, expect_ou=False))
    return summary


def run_negative_tests(org_id, ss_id):
    print('\n══════════════════════════════════════')
    print('  NEGATIVE TESTS')
    print('══════════════════════════════════════')

    cnf = BASE_CNF.replace('{ou_placeholder}', ss_id)
    summary = []

    summary.append(_negative(
        'N1: Invalid organizationIdentifier (missing VATBR- prefix)', org_id, ss_id,
        cnf.replace('organizationIdentifier = VATBR-889333566138222',
                    'organizationIdentifier = 889333566138222')
    ))
    summary.append(_negative('N2: Unsupported key size (1024-bit RSA)', org_id, ss_id, cnf, key_size=1024))
    summary.append(_negative('N3: Weak signature algorithm (SHA-1)', org_id, ss_id, cnf, extra_args=['-sha1']))
    summary.append(_negative(
        'N4: CA:TRUE in Basic Constraints', org_id, ss_id,
        cnf.replace('[ req_cert_extensions ]',
                    '[ req_cert_extensions ]\nbasicConstraints = critical, CA:TRUE')
    ))
    summary.append(_negative(
        'N5: Missing subjectAltName (known gap)', org_id, ss_id,
        cnf.replace('req_extensions = req_cert_extensions\n', '')
    ))
    summary.append(_negative(
        'N6: Custom/unknown extension', org_id, ss_id,
        cnf.replace('[ req_cert_extensions ]\nsubjectAltName = @alt_name',
                    '[ req_cert_extensions ]\nsubjectAltName = @alt_name\n1.2.3.4.5.6.7.8 = ASN1:UTF8String:CustomValue')
    ))
    summary.append(_negative('N7a: Missing CN', org_id, ss_id,
                              cnf.replace('commonName = Cypress_03_09_2025_1f333acfe\n', '')))
    summary.append(_negative('N7b: Missing O (organizationName)', org_id, ss_id,
                              cnf.replace('organizationName = Cypress Org Own\n', '')))
    summary.append(_negative('N7c: Missing organizationIdentifier', org_id, ss_id,
                              cnf.replace('organizationIdentifier = VATBR-889333566138222\n', '')))
    summary.append(_negative(
        'N8: Empty/blank field values', org_id, ss_id,
        cnf.replace('organizationName = Cypress Org Own', 'organizationName = " "')
           .replace('commonName = Cypress_03_09_2025_1f333acfe', 'commonName = " "')
    ))
    summary.append(_negative(
        'N9: Invalid key usage (keyCertSign, cRLSign)', org_id, ss_id,
        cnf.replace('[ req_cert_extensions ]\nsubjectAltName = @alt_name',
                    '[ req_cert_extensions ]\nsubjectAltName = @alt_name\nkeyUsage = critical, keyCertSign, cRLSign')
    ))
    return summary


def _positive(name, org_id, ss_id, cnf_content, expect_ou=True):
    print(f'\n  [{name}]')
    try:
        csr_pem = generate_csr(cnf_content)
    except RuntimeError as e:
        print(f'    ❌ CSR generation failed: {e}')
        return (name, False)

    response = submit_csr(org_id, ss_id, csr_pem)
    print(f'    Response: {response.status_code}')

    if response.status_code != 201:
        print(f'    ❌ Expected 201, got {response.status_code}: {response.text}')
        return (name, False)

    cert_pem = extract_cert_pem(response)
    if not cert_pem:
        print(f'    ❌ Could not extract PEM from response')
        return (name, False)

    passed = verify_certificate(cert_pem, expect_ou=expect_ou)
    return (name, passed)


def _negative(name, org_id, ss_id, cnf_content, key_size=2048, extra_args=None):
    print(f'\n  [{name}]')
    try:
        csr_pem = generate_csr(cnf_content, key_size=key_size, extra_args=extra_args)
    except RuntimeError as e:
        print(f'    ❌ CSR generation failed: {e}')
        return (name, False)

    response = submit_csr(org_id, ss_id, csr_pem)
    print(f'    Response: {response.status_code}')

    if response.status_code in (400, 422):
        error = response.json().get('errors', response.text)
        print(f'    ✅ Correctly rejected — {error}')
        return (name, True)
    elif response.status_code == 201:
        print(f'    ❌ Expected rejection but certificate was issued (gap identified)')
        return (name, False)
    else:
        print(f'    ⚠️  Unexpected status {response.status_code}: {response.text}')
        return (name, False)


def submit_csr(org_id, ss_id, csr_pem):
    return api_post(
        f'/organisations/{org_id}/softwarestatements/{ss_id}/certificates/{CERT_TYPE}',
        data=csr_pem,
        content_type='application/x-pem-file'
    )


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(org_id, ss_id, summary):
    print('\n══════════════════════════════════════')
    print('  SUMMARY')
    print('══════════════════════════════════════')
    print(f'  Org ID : {org_id}')
    print(f'  SS ID  : {ss_id}')
    print()
    print(f'  {"Test":<50} {"Result"}')
    print(f'  {"-"*60}')
    for name, passed in summary:
        print(f'  {name:<50} {"✅ Pass" if passed else "❌ Fail"}')
    passed_count = sum(1 for _, p in summary if p)
    print(f'\n  {passed_count}/{len(summary)} tests passed.')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    org_id, ss_id = setup()
    summary = run_positive_tests(org_id, ss_id)
    summary += run_negative_tests(org_id, ss_id)
    print_summary(org_id, ss_id, summary)


if __name__ == '__main__':
    main()