import socket
import httpx
from twilight_orbit.config import GEO_API_URL, DEFAULT_TIMEOUT

def run(target: str) -> dict:
    results = {'module': 'IP Geolocation', 'target': target, 'ip': None, 'location': {}, 'errors': []}
    try:
        ip = socket.gethostbyname(target)
        results['ip'] = ip
    except socket.gaierror:
        results['errors'].append(f'Could not resolve {target} to an IP address')
        return results
    try:
        url = GEO_API_URL.replace('{ip}', ip)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            data = response.json()
            if data.get('status') == 'success':
                results['location'] = {'country': data.get('country', 'Unknown'), 'region': data.get('regionName', 'Unknown'), 'city': data.get('city', 'Unknown'), 'zip': data.get('zip', ''), 'latitude': data.get('lat'), 'longitude': data.get('lon'), 'timezone': data.get('timezone', ''), 'isp': data.get('isp', 'Unknown'), 'organization': data.get('org', 'Unknown'), 'as_number': data.get('as', 'Unknown')}
            else:
                results['errors'].append(f"Geolocation failed: {data.get('message', 'Unknown error')}")
    except httpx.TimeoutException:
        results['errors'].append('Geolocation API request timed out')
    except Exception as e:
        results['errors'].append(f'Geolocation error: {str(e)}')
    return results