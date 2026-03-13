import ssl
import socket
from datetime import datetime, timezone
from twilight_orbit.config import DEFAULT_TIMEOUT

def run(target: str, port: int=443) -> dict:
    results = {'module': 'SSL/TLS Info', 'target': target, 'port': port, 'certificate': {}, 'errors': []}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert is None:
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as sock2:
                            with ctx2.wrap_socket(sock2, server_hostname=target) as ssock2:
                                cert = ssock2.getpeercert()
                    except ssl.SSLCertVerificationError:
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            results['certificate']['raw_der_length'] = len(der_cert)
                            results['certificate']['note'] = 'Certificate verification failed — possibly self-signed'
                        results['errors'].append('SSL certificate verification failed')
                        results['certificate']['protocol'] = ssock.version()
                        results['certificate']['cipher'] = ssock.cipher()
                        return results
                if cert:
                    subject = {}
                    for item in cert.get('subject', ()):
                        for key, value in item:
                            subject[key] = value
                    results['certificate']['subject'] = subject
                    issuer = {}
                    for item in cert.get('issuer', ()):
                        for key, value in item:
                            issuer[key] = value
                    results['certificate']['issuer'] = issuer
                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')
                    results['certificate']['not_before'] = not_before
                    results['certificate']['not_after'] = not_after
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_until_expiry = (expiry - now).days
                            results['certificate']['days_until_expiry'] = days_until_expiry
                            results['certificate']['expired'] = days_until_expiry < 0
                        except ValueError:
                            pass
                    san = cert.get('subjectAltName', ())
                    results['certificate']['san'] = [name for _, name in san]
                    results['certificate']['serial_number'] = cert.get('serialNumber', '')
                    results['certificate']['version'] = cert.get('version', '')
                results['certificate']['protocol'] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    results['certificate']['cipher'] = {'name': cipher[0], 'protocol': cipher[1], 'bits': cipher[2]}
    except socket.timeout:
        results['errors'].append(f'Connection to {target}:{port} timed out')
    except ConnectionRefusedError:
        results['errors'].append(f'Connection to {target}:{port} refused — SSL not available')
    except socket.gaierror:
        results['errors'].append(f'Could not resolve {target}')
    except Exception as e:
        results['errors'].append(f'SSL analysis error: {str(e)}')
    return results