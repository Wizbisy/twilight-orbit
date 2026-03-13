import httpx
from twilight_orbit.config import SECURITY_HEADERS, DEFAULT_TIMEOUT

def run(target: str) -> dict:
    results = {'module': 'HTTP Headers', 'target': target, 'url': None, 'status_code': None, 'headers': {}, 'security_analysis': [], 'score': 0, 'max_score': len(SECURITY_HEADERS), 'server': None, 'errors': []}
    urls = [f'https://{target}', f'http://{target}']
    for url in urls:
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=True, verify=False) as client:
                response = client.get(url)
                results['url'] = str(response.url)
                results['status_code'] = response.status_code
                results['headers'] = dict(response.headers)
                results['server'] = response.headers.get('server', 'Not disclosed')
                present_count = 0
                for header_name, info in SECURITY_HEADERS.items():
                    header_value = response.headers.get(header_name.lower())
                    is_present = header_value is not None
                    if is_present:
                        present_count += 1
                    results['security_analysis'].append({'header': header_name, 'present': is_present, 'value': header_value or 'Not set', 'description': info['description'], 'severity': info['severity']})
                results['score'] = present_count
                interesting = {}
                for key in ['x-powered-by', 'x-aspnet-version', 'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-cache']:
                    val = response.headers.get(key)
                    if val:
                        interesting[key] = val
                if interesting:
                    results['interesting_headers'] = interesting
                return results
        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            results['errors'].append(f'Timeout connecting to {url}')
            continue
        except Exception as e:
            results['errors'].append(f'Error connecting to {url}: {str(e)}')
            continue
    if not results['url']:
        results['errors'].append(f'Could not connect to {target} on HTTP or HTTPS')
    return results