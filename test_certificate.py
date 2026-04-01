import os
import re
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
CNF_PATH = f'certs/{ORG}/{ENV}/wrpac.cnf'


def load_base_cnf(ss_id=None):
    with open(CNF_PATH, 'r') as f:
        cnf = f.read()
    if ss_id:
        cnf = re.sub(r'organizationalUnitName\s*=\s*.+', f'organizationalUnitName = {ss_id}', cnf)
    return cnf


# ── Setup ────────────────────────────────────────────────────────────────────

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


def create_organisation():
    org_id = str(uuid.uuid4())
    org_name = f'CertAutoTest Org {org_id[:8]}'

    payload = {
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
    }

    response = api_post('/organisations/', payload)
    if response.status_code == 201:
        print(f'  ✅ Organisation created: {org_name} ({org_id})')
        return org_id
    else:
        raise RuntimeError(f'Failed to create organisation [{response.status_code}]: {response.text}')


def fetch_authority_domain():
    """Fetch the first available authority, domain and role from the environment."""
    import requests as _requests

    # Get authority-domain mappings
    r = _requests.get(
        f'{BASE_URL}/references/authorityauthorisationdomains',
        headers=HEADERS, cert=CERT, verify=False
    )
    if r.status_code != 200:
        raise RuntimeError(f'Failed to fetch authority domains [{r.status_code}]: {r.text}')

    items = r.json()
    if isinstance(items, dict):
        items = items.get('Data', items.get('content', []))

    if not items:
        raise RuntimeError('No authority-domain mappings found in this environment')

    entry = items[0]
    authority_id = entry.get('AuthorityID') or entry.get('AuthorityId')
    authority_name = entry.get('AuthorityName')
    domain_name = entry.get('AuthorisationDomainName')

    # Get a role for this domain
    r2 = _requests.get(
        f'{BASE_URL}/references/authorisationdomains/{domain_name}/authorisationdomainroles',
        headers=HEADERS, cert=CERT, verify=False
    )
    if r2.status_code != 200:
        raise RuntimeError(f'Failed to fetch domain roles [{r2.status_code}]: {r2.text}')

    roles = r2.json()
    if isinstance(roles, dict):
        roles = roles.get('Data', roles.get('content', []))

    active_roles = [r for r in roles if r.get('Status') == 'Active']
    if not active_roles:
        raise RuntimeError(f'No active roles found for domain {domain_name}')

    role_name = active_roles[0].get('AuthorisationDomainRoleName')

    print(f'  ℹ️  Using authority={authority_name} ({authority_id}), domain={domain_name}, role={role_name}')
    return authority_id, authority_name, domain_name, role_name


def create_authority_domain_claim(org_id, authority_id, authority_name, domain_name):
    payload = {
        'AuthorisationDomainName': domain_name,
        'AuthorityId': authority_id,
        'AuthorityName': authority_name
    }
    response = api_post(f'/organisations/{org_id}/authoritydomainclaims', payload)
    if response.status_code == 201:
        print(f'  ✅ Authority domain claim created')
    else:
        raise RuntimeError(f'Failed to create authority domain claim [{response.status_code}]: {response.text}')


def create_authority_claim(org_id, authority_id, domain_name, role_name):
    payload = {
        'AuthorityId': authority_id,
        'Status': 'Active',
        'AuthorisationDomain': domain_name,
        'Role': role_name,
        'RegistrationId': 'REG123'
    }
    response = api_post(f'/organisations/{org_id}/authorityclaims', payload)
    if response.status_code == 201:
        print(f'  ✅ Authority claim created')
    else:
        raise RuntimeError(f'Failed to create authority claim [{response.status_code}]: {response.text}')


def create_software_statement(org_id, domain_name, role_name):
    run_id = str(uuid.uuid4())[:8]
    ss_name = f'CertAutoTest SS {run_id}'

    payload = {
        'ClientName': ss_name,
        'Description': 'Created by cert auto-test script',
        'LogoUri': 'https://www.example.com/file.svg',
        'RedirectUri': ['https://www.example.com/file.svg'],
        'Version': 40,
        'ClientUri': 'https://www.example.com',
        'Roles': [
            {
                'Status': 'Active',
                'AuthorisationDomain': domain_name,
                'Role': role_name
            }
        ]
    }

    response = api_post(f'/organisations/{org_id}/softwarestatements', payload)
    if response.status_code == 201:
        ss_id = response.json().get('SoftwareStatementId')
        print(f'  ✅ Software Statement created: {ss_name} ({ss_id})')
        return ss_id
    else:
        raise RuntimeError(f'Failed to create software statement [{response.status_code}]: {response.text}')


# ── CSR Generation ───────────────────────────────────────────────────────────

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


# ── API Interaction ──────────────────────────────────────────────────────────

def submit_csr(org_id, ss_id, csr_pem):
    return api_post(
        f'/organisations/{org_id}/softwarestatements/{ss_id}/certificates/{CERT_TYPE}',
        data=csr_pem,
        content_type='application/x-pem-file'
    )


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


# ── Certificate Verification ─────────────────────────────────────────────────

def verify_certificate(cert_pem, expect_ou=True):
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    subject = cert.subject
    results = []

    def check(name, passed, detail=''):
        status = '✅ Pass' if passed else '❌ Fail'
        msg = f'{status} — {detail}' if detail else status
        results.append((name, passed))
        print(f'    {name}: {msg}')

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

    return all(r[1] for r in results)


# ── Test Runners ─────────────────────────────────────────────────────────────

def run_positive_test(name, org_id, ss_id, cnf_content, expect_ou=True):
    print(f'\n  [{name}]')
    try:
        csr_pem = generate_csr(cnf_content)
    except RuntimeError as e:
        print(f'    ❌ CSR generation failed: {e}')
        return False, 'CSR generation failed'

    response = submit_csr(org_id, ss_id, csr_pem)
    print(f'    Response: {response.status_code}')

    if response.status_code != 201:
        print(f'    ❌ Expected 201, got {response.status_code}: {response.text}')
        return False, f'Expected 201, got {response.status_code}'

    cert_pem = extract_cert_pem(response)
    if not cert_pem:
        print(f'    ❌ Could not extract PEM from response')
        return False, 'Could not extract PEM'

    passed = verify_certificate(cert_pem, expect_ou=expect_ou)
    return passed, 'All checks passed' if passed else 'Some checks failed'


def run_negative_test(name, org_id, ss_id, cnf_content, key_size=2048, extra_args=None):
    print(f'\n  [{name}]')
    try:
        csr_pem = generate_csr(cnf_content, key_size=key_size, extra_args=extra_args)
    except RuntimeError as e:
        print(f'    ❌ CSR generation failed: {e}')
        return False, 'CSR generation failed'

    response = submit_csr(org_id, ss_id, csr_pem)
    print(f'    Response: {response.status_code}')

    if response.status_code in (400, 422):
        error = response.json().get('errors', response.text)
        print(f'    ✅ Correctly rejected — {error}')
        return True, f'Correctly rejected: {error}'
    elif response.status_code == 201:
        print(f'    ❌ Expected rejection but certificate was issued (gap identified)')
        return False, 'Certificate issued — not rejected (gap)'
    else:
        print(f'    ⚠️  Unexpected status {response.status_code}: {response.text}')
        return False, f'Unexpected status {response.status_code}'


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    summary = []

    print('\n══════════════════════════════════════')
    print('  SETUP')
    print('══════════════════════════════════════')
    authority_id, authority_name, domain_name, role_name = fetch_authority_domain()
    org_id = create_organisation()
    create_authority_domain_claim(org_id, authority_id, authority_name, domain_name)
    create_authority_claim(org_id, authority_id, domain_name, role_name)
    ss_id = create_software_statement(org_id, domain_name, role_name)

    cnf_with_ou = load_base_cnf(ss_id=ss_id)
    cnf_without_ou = re.sub(r'organizationalUnitName\s*=\s*.+\n', '', cnf_with_ou)

    print('\n══════════════════════════════════════')
    print('  POSITIVE TESTS')
    print('══════════════════════════════════════')

    passed, detail = run_positive_test('P1: Valid CSR with OU', org_id, ss_id, cnf_with_ou, expect_ou=True)
    summary.append(('P1', 'Valid CSR with OU', passed, detail))

    passed, detail = run_positive_test('P2: Valid CSR without OU', org_id, ss_id, cnf_without_ou, expect_ou=False)
    summary.append(('P2', 'Valid CSR without OU', passed, detail))

    print('\n══════════════════════════════════════')
    print('  NEGATIVE TESTS')
    print('══════════════════════════════════════')

    cnf = cnf_with_ou.replace('organizationIdentifier = VATBR-889333566138222',
                               'organizationIdentifier = 889333566138222')
    passed, detail = run_negative_test('N1: Invalid organizationIdentifier (missing VATBR- prefix)', org_id, ss_id, cnf)
    summary.append(('N1', 'Invalid organizationIdentifier format', passed, detail))

    passed, detail = run_negative_test('N2: Unsupported key size (1024-bit RSA)', org_id, ss_id, cnf_with_ou, key_size=1024)
    summary.append(('N2', 'Unsupported key size (1024-bit RSA)', passed, detail))

    passed, detail = run_negative_test('N3: Weak signature algorithm (SHA-1)', org_id, ss_id, cnf_with_ou, extra_args=['-sha1'])
    summary.append(('N3', 'Weak signature algorithm (SHA-1)', passed, detail))

    cnf = cnf_with_ou.replace('[ req_cert_extensions ]',
                               '[ req_cert_extensions ]\nbasicConstraints = critical, CA:TRUE')
    passed, detail = run_negative_test('N4: CA:TRUE in Basic Constraints', org_id, ss_id, cnf)
    summary.append(('N4', 'CA:TRUE in Basic Constraints', passed, detail))

    cnf = cnf_with_ou.replace('req_extensions = req_cert_extensions\n', '')
    passed, detail = run_negative_test('N5: Missing subjectAltName (known gap)', org_id, ss_id, cnf)
    summary.append(('N5', 'Missing subjectAltName', passed, detail))

    cnf = cnf_with_ou.replace(
        '[ req_cert_extensions ]\nsubjectAltName = @alt_name',
        '[ req_cert_extensions ]\nsubjectAltName = @alt_name\n1.2.3.4.5.6.7.8 = ASN1:UTF8String:CustomValue'
    )
    passed, detail = run_negative_test('N6: Custom/unknown extension', org_id, ss_id, cnf)
    summary.append(('N6', 'Custom/unknown extension', passed, detail))

    cnf = cnf_with_ou.replace('commonName = Cypress_03_09_2025_1f333acfe\n', '')
    passed, detail = run_negative_test('N7a: Missing CN', org_id, ss_id, cnf)
    summary.append(('N7a', 'Missing CN', passed, detail))

    cnf = cnf_with_ou.replace('organizationName = Cypress Org Own\n', '')
    passed, detail = run_negative_test('N7b: Missing O (organizationName)', org_id, ss_id, cnf)
    summary.append(('N7b', 'Missing O (organizationName)', passed, detail))

    cnf = cnf_with_ou.replace('organizationIdentifier = VATBR-889333566138222\n', '')
    passed, detail = run_negative_test('N7c: Missing organizationIdentifier', org_id, ss_id, cnf)
    summary.append(('N7c', 'Missing organizationIdentifier', passed, detail))

    cnf = cnf_with_ou.replace('organizationName = Cypress Org Own', 'organizationName = " "')
    cnf = cnf.replace('commonName = Cypress_03_09_2025_1f333acfe', 'commonName = " "')
    passed, detail = run_negative_test('N8: Empty/blank field values', org_id, ss_id, cnf)
    summary.append(('N8', 'Empty/blank field values', passed, detail))

    cnf = cnf_with_ou.replace(
        '[ req_cert_extensions ]\nsubjectAltName = @alt_name',
        '[ req_cert_extensions ]\nsubjectAltName = @alt_name\nkeyUsage = critical, keyCertSign, cRLSign'
    )
    passed, detail = run_negative_test('N9: Invalid key usage (keyCertSign, cRLSign)', org_id, ss_id, cnf)
    summary.append(('N9', 'Invalid key usage (keyCertSign, cRLSign)', passed, detail))

    print('\n══════════════════════════════════════')
    print('  SUMMARY')
    print('══════════════════════════════════════')
    print(f'  Org ID : {org_id}')
    print(f'  SS ID  : {ss_id}')
    print()
    print(f'  {"Test":<5} {"Scenario":<45} {"Result"}')
    print(f'  {"-"*65}')
    for test_id, scenario, passed, _ in summary:
        result = '✅ Pass' if passed else '❌ Fail'
        print(f'  {test_id:<5} {scenario:<45} {result}')

    total = len(summary)
    passed_count = sum(1 for _, _, p, _ in summary if p)
    print(f'\n  {passed_count}/{total} tests passed.')


if __name__ == '__main__':
    main()