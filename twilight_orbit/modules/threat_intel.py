import socket
import httpx
from twilight_orbit.config import OTX_DOMAIN_URL, OTX_IP_URL, THREATFOX_API_URL, HACKERTARGET_REVERSE_DNS, HACKERTARGET_PAGE_LINKS, URLSCAN_SEARCH_URL, DEFAULT_TIMEOUT

def _query_otx(target: str, ip: str | None) -> dict:
    otx_data = {'pulses': 0, 'reputation': None, 'tags': [], 'references': []}
    try:
        url = OTX_DOMAIN_URL.replace('{domain}', target)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                otx_data['pulses'] = pulse_info.get('count', 0)
                otx_data['reputation'] = data.get('reputation', 0)
                for pulse in pulse_info.get('pulses', [])[:5]:
                    otx_data['tags'].extend(pulse.get('tags', []))
                    refs = pulse.get('references', [])
                    otx_data['references'].extend(refs[:3])
                otx_data['tags'] = list(set(otx_data['tags']))[:15]
                otx_data['references'] = list(set(otx_data['references']))[:5]
                otx_data['alexa_rank'] = data.get('alexa', 'N/A')
                sections = data.get('sections', [])
                otx_data['sections_available'] = sections
    except Exception:
        pass
    return otx_data

def _query_urlscan(target: str) -> list:
    scans = []
    try:
        url = URLSCAN_SEARCH_URL.replace('{domain}', target)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', [])[:5]:
                    page = result.get('page', {})
                    task = result.get('task', {})
                    scans.append({'url': page.get('url', ''), 'domain': page.get('domain', ''), 'ip': page.get('ip', ''), 'server': page.get('server', ''), 'country': page.get('country', ''), 'scan_date': task.get('time', ''), 'report_url': f"https://urlscan.io/result/{result.get('_id', '')}/", 'screenshot': f"https://urlscan.io/screenshots/{result.get('_id', '')}.png"})
    except Exception:
        pass
    return scans

def _query_threatfox(target: str) -> dict:
    threat_data = {'iocs': [], 'is_malicious': False}
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.post(THREATFOX_API_URL, json={'query': 'search_ioc', 'search_term': target})
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    iocs = data.get('data', [])
                    if iocs:
                        threat_data['is_malicious'] = True
                        for ioc in iocs[:10]:
                            threat_data['iocs'].append({'ioc': ioc.get('ioc', ''), 'threat_type': ioc.get('threat_type', ''), 'malware': ioc.get('malware_printable', ''), 'confidence': ioc.get('confidence_level', 0), 'first_seen': ioc.get('first_seen_utc', ''), 'reporter': ioc.get('reporter', '')})
    except Exception:
        pass
    return threat_data

def _query_reverse_dns(ip: str) -> list:
    domains = []
    try:
        url = HACKERTARGET_REVERSE_DNS.replace('{ip}', ip)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    line = line.strip()
                    if line and 'API count' not in line:
                        domains.append(line)
    except Exception:
        pass
    return domains[:20]

def _query_page_links(target: str) -> list:
    links = []
    try:
        url = HACKERTARGET_PAGE_LINKS.replace('{target}', target)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    line = line.strip()
                    if line and line.startswith('http') and ('API count' not in line):
                        links.append(line)
    except Exception:
        pass
    return links[:30]

def run(target: str) -> dict:
    results = {'module': 'Threat Intelligence', 'target': target, 'risk_level': 'UNKNOWN', 'otx': {}, 'urlscan': [], 'threatfox': {}, 'reverse_dns': [], 'page_links': [], 'errors': []}
    ip = None
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        pass
    try:
        results['otx'] = _query_otx(target, ip)
    except Exception as e:
        results['errors'].append(f'OTX error: {str(e)}')
    try:
        results['urlscan'] = _query_urlscan(target)
    except Exception as e:
        results['errors'].append(f'URLScan error: {str(e)}')
    try:
        results['threatfox'] = _query_threatfox(target)
    except Exception as e:
        results['errors'].append(f'ThreatFox error: {str(e)}')
    if ip:
        try:
            results['reverse_dns'] = _query_reverse_dns(ip)
        except Exception as e:
            results['errors'].append(f'Reverse DNS error: {str(e)}')
    try:
        results['page_links'] = _query_page_links(target)
    except Exception as e:
        results['errors'].append(f'Page links error: {str(e)}')
    risk_score = 0
    if results['threatfox'].get('is_malicious'):
        risk_score += 5
    otx_pulses = results['otx'].get('pulses', 0)
    if otx_pulses > 10:
        risk_score += 3
    elif otx_pulses > 0:
        risk_score += 1
    if risk_score >= 5:
        results['risk_level'] = 'HIGH'
    elif risk_score >= 2:
        results['risk_level'] = 'MEDIUM'
    elif risk_score >= 1:
        results['risk_level'] = 'LOW'
    else:
        results['risk_level'] = 'CLEAN'
    return results