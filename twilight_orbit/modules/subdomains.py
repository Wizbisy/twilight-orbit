import os
import dns.resolver
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from twilight_orbit.config import DEFAULT_DNS_TIMEOUT, CRT_SH_URL, SECURITYTRAILS_API_URL
DEFAULT_SUBDOMAINS = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'ntp', 'imap', 'pop3', 'admin', 'administrator', 'api', 'app', 'apps', 'beta', 'blog', 'cdn', 'cloud', 'cms', 'cpanel', 'dashboard', 'db', 'dev', 'developer', 'docs', 'email', 'exchange', 'files', 'forum', 'git', 'gitlab', 'help', 'home', 'host', 'hub', 'images', 'img', 'internal', 'intranet', 'jenkins', 'jira', 'lab', 'labs', 'ldap', 'legacy', 'login', 'manage', 'media', 'mobile', 'monitor', 'mysql', 'new', 'news', 'office', 'old', 'ops', 'oracle', 'panel', 'portal', 'preview', 'prod', 'production', 'proxy', 'rdp', 'redis', 'registry', 'remote', 'repo', 'reports', 'rest', 'sandbox', 'search', 'secure', 'server', 'shop', 'sip', 'sitemap', 'ssh', 'ssl', 'staging', 'static', 'status', 'store', 'support', 'sync', 'syslog', 'test', 'testing', 'ticket', 'tools', 'tracker', 'upload', 'vault', 'video', 'vm', 'vpn', 'web', 'webdisk', 'wiki', 'www1', 'www2', 'www3']

def _resolve_subdomain(subdomain: str, target: str, timeout: float) -> str | None:
    fqdn = f'{subdomain}.{target}'
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        resolver.resolve(fqdn, 'A')
        return fqdn
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None

def _query_crt_sh(target: str) -> list[str]:
    subdomains = set()
    try:
        url = CRT_SH_URL.replace('{domain}', target)
        with httpx.Client(timeout=15, verify=False) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for line in name.split('\n'):
                        line = line.strip().lower()
                        if line.endswith(f'.{target}') or line == target:
                            if '*' not in line:
                                subdomains.add(line)
    except Exception:
        pass
    return list(subdomains)

def _load_wordlist(wordlist_path: str | None) -> list[str]:
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    return DEFAULT_SUBDOMAINS

def run(target: str, wordlist: str | None=None, threads: int=30) -> dict:
    results = {'module': 'Subdomain Discovery', 'target': target, 'subdomains': [], 'sources': {'bruteforce': [], 'crt_sh': []}, 'total': 0, 'errors': []}
    discovered = set()
    wordlist_items = _load_wordlist(wordlist)
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_resolve_subdomain, sub, target, DEFAULT_DNS_TIMEOUT): sub for sub in wordlist_items}
            for future in as_completed(futures):
                result = future.result()
                if result and result not in discovered:
                    discovered.add(result)
                    results['sources']['bruteforce'].append(result)
    except Exception as e:
        results['errors'].append(f'Brute-force error: {str(e)}')
    try:
        crt_results = _query_crt_sh(target)
        for sub in crt_results:
            if sub not in discovered:
                discovered.add(sub)
                results['sources']['crt_sh'].append(sub)
    except Exception as e:
        results['errors'].append(f'crt.sh error: {str(e)}')
    st_key = os.getenv('SECURITYTRAILS_API_KEY')
    if st_key:
        try:
            url = SECURITYTRAILS_API_URL.replace('{target}', target)
            headers = {'APIKEY': st_key, 'accept': 'application/json'}
            with httpx.Client(timeout=10, headers=headers, verify=False) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if 'subdomains' in data:
                        for prefix in data['subdomains']:
                            full_sub = f'{prefix}.{target}'
                            if full_sub not in discovered:
                                discovered.add(full_sub)
                                if 'securitytrails' not in results['sources']:
                                    results['sources']['securitytrails'] = []
                                results['sources']['securitytrails'].append(full_sub)
                elif res.status_code in [401, 403]:
                    results['errors'].append('SecurityTrails API Key is invalid or unauthorized')
        except Exception as e:
            results['errors'].append(f'SecurityTrails API error: {str(e)}')
    results['subdomains'] = sorted(list(discovered))
    results['total'] = len(discovered)
    return results