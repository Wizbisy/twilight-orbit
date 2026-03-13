import httpx
from twilight_orbit.config import WAYBACK_API_URL, DEFAULT_TIMEOUT

def run(target: str) -> dict:
    results = {'module': 'Wayback Machine', 'target': target, 'snapshots': [], 'has_archive': False, 'errors': []}
    try:
        url = WAYBACK_API_URL.replace('{target}', target)
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                snapshots = data.get('archived_snapshots', {})
                closest = snapshots.get('closest')
                if closest:
                    results['has_archive'] = True
                    results['snapshots'].append({'url': closest.get('url', ''), 'timestamp': closest.get('timestamp', ''), 'status': closest.get('status', ''), 'available': closest.get('available', False)})
    except Exception as e:
        results['errors'].append(f'Wayback API error: {str(e)}')
    try:
        cdx_url = f'https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=20&fl=timestamp,statuscode,original,mimetype&collapse=timestamp:6'
        with httpx.Client(timeout=15) as client:
            response = client.get(cdx_url)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    headers = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers, row))
                        ts = entry.get('timestamp', '')
                        formatted_date = f'{ts[:4]}-{ts[4:6]}-{ts[6:8]}' if len(ts) >= 8 else ts
                        results['snapshots'].append({'url': f"https://web.archive.org/web/{ts}/{entry.get('original', '')}", 'timestamp': formatted_date, 'status': entry.get('statuscode', ''), 'mimetype': entry.get('mimetype', '')})
                    results['has_archive'] = True
                    results['total_snapshots'] = len(data) - 1
    except Exception as e:
        results['errors'].append(f'CDX API error: {str(e)}')
    return results