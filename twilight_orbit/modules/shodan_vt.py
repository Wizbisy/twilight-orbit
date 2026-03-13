import os
import socket
import httpx
from twilight_orbit.config import DEFAULT_TIMEOUT

def _query_shodan(ip: str) -> dict:
    api_key = os.environ.get('SHODAN_API_KEY')
    if not api_key:
        return {'available': False, 'note': 'Set SHODAN_API_KEY env var for Shodan data (free at shodan.io)'}
    data = {'available': True}
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}?key={api_key}'
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200:
                result = response.json()
                data['ip'] = result.get('ip_str', ip)
                data['organization'] = result.get('org', '')
                data['os'] = result.get('os', 'Unknown')
                data['ports'] = result.get('ports', [])
                data['hostnames'] = result.get('hostnames', [])
                data['country'] = result.get('country_name', '')
                data['city'] = result.get('city', '')
                data['isp'] = result.get('isp', '')
                data['vulns'] = result.get('vulns', [])
                data['last_update'] = result.get('last_update', '')
                services = []
                for item in result.get('data', [])[:10]:
                    services.append({'port': item.get('port', 0), 'transport': item.get('transport', 'tcp'), 'product': item.get('product', ''), 'version': item.get('version', ''), 'banner': item.get('data', '')[:200]})
                data['services'] = services
            elif response.status_code == 401:
                data['error'] = 'Invalid Shodan API key'
            elif response.status_code == 404:
                data['note'] = 'No Shodan data found for this IP'
            else:
                data['error'] = f'Shodan API returned {response.status_code}'
    except Exception as e:
        data['error'] = str(e)
    return data

def _query_virustotal(target: str) -> dict:
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {'available': False, 'note': 'Set VIRUSTOTAL_API_KEY env var for VirusTotal data (free at virustotal.com)'}
    data = {'available': True}
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{target}'
        headers = {'x-apikey': api_key}
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                attrs = result.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                data['malicious'] = stats.get('malicious', 0)
                data['suspicious'] = stats.get('suspicious', 0)
                data['harmless'] = stats.get('harmless', 0)
                data['undetected'] = stats.get('undetected', 0)
                data['total_engines'] = sum(stats.values())
                data['reputation'] = attrs.get('reputation', 0)
                data['categories'] = attrs.get('categories', {})
                data['creation_date'] = attrs.get('creation_date', '')
                data['last_analysis_date'] = attrs.get('last_analysis_date', '')
                data['registrar'] = attrs.get('registrar', '')
                data['whois'] = attrs.get('whois', '')[:500]
                if data['malicious'] > 3:
                    data['verdict'] = 'MALICIOUS'
                elif data['malicious'] > 0 or data['suspicious'] > 0:
                    data['verdict'] = 'SUSPICIOUS'
                else:
                    data['verdict'] = 'CLEAN'
            elif response.status_code == 401:
                data['error'] = 'Invalid VirusTotal API key'
            else:
                data['error'] = f'VirusTotal API returned {response.status_code}'
    except Exception as e:
        data['error'] = str(e)
    return data

def _query_abuseipdb(ip: str) -> dict:
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'available': False, 'note': 'Set ABUSEIPDB_API_KEY env var for abuse data (free at abuseipdb.com)'}
    data = {'available': True}
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                result = response.json().get('data', {})
                data['ip'] = result.get('ipAddress', ip)
                data['is_public'] = result.get('isPublic', True)
                data['abuse_confidence_score'] = result.get('abuseConfidenceScore', 0)
                data['country'] = result.get('countryCode', '')
                data['isp'] = result.get('isp', '')
                data['domain'] = result.get('domain', '')
                data['is_tor'] = result.get('isTor', False)
                data['total_reports'] = result.get('totalReports', 0)
                data['last_reported'] = result.get('lastReportedAt', '')
                data['usage_type'] = result.get('usageType', '')
                reports = result.get('reports', [])[:5]
                data['recent_reports'] = [{'reported_at': r.get('reportedAt', ''), 'comment': r.get('comment', '')[:200], 'categories': r.get('categories', [])} for r in reports]
            elif response.status_code == 401:
                data['error'] = 'Invalid AbuseIPDB API key'
            else:
                data['error'] = f'AbuseIPDB API returned {response.status_code}'
    except Exception as e:
        data['error'] = str(e)
    return data

def run(target: str) -> dict:
    results = {'module': 'Shodan / VirusTotal / AbuseIPDB', 'target': target, 'shodan': {}, 'virustotal': {}, 'abuseipdb': {}, 'api_keys_configured': [], 'errors': []}
    if os.environ.get('SHODAN_API_KEY'):
        results['api_keys_configured'].append('Shodan')
    if os.environ.get('VIRUSTOTAL_API_KEY'):
        results['api_keys_configured'].append('VirusTotal')
    if os.environ.get('ABUSEIPDB_API_KEY'):
        results['api_keys_configured'].append('AbuseIPDB')
    ip = None
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        results['errors'].append(f'Could not resolve {target}')
    if ip:
        try:
            results['shodan'] = _query_shodan(ip)
        except Exception as e:
            results['errors'].append(f'Shodan error: {str(e)}')
    try:
        results['virustotal'] = _query_virustotal(target)
    except Exception as e:
        results['errors'].append(f'VirusTotal error: {str(e)}')
    if ip:
        try:
            results['abuseipdb'] = _query_abuseipdb(ip)
        except Exception as e:
            results['errors'].append(f'AbuseIPDB error: {str(e)}')
    return results