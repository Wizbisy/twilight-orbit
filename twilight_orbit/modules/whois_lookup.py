import whois

def run(target: str) -> dict:
    results = {'module': 'WHOIS Lookup', 'target': target, 'data': {}, 'errors': []}
    try:
        w = whois.whois(target)

        def _normalize(value):
            if value is None:
                return None
            if isinstance(value, list):
                return [str(v) for v in value]
            return str(value)
        results['data'] = {'domain_name': _normalize(w.domain_name), 'registrar': _normalize(w.registrar), 'whois_server': _normalize(w.whois_server), 'creation_date': _normalize(w.creation_date), 'expiration_date': _normalize(w.expiration_date), 'updated_date': _normalize(w.updated_date), 'name_servers': _normalize(w.name_servers), 'status': _normalize(w.status), 'emails': _normalize(w.emails), 'registrant': _normalize(getattr(w, 'name', None)), 'organization': _normalize(getattr(w, 'org', None)), 'country': _normalize(getattr(w, 'country', None)), 'state': _normalize(getattr(w, 'state', None)), 'city': _normalize(getattr(w, 'city', None)), 'dnssec': _normalize(getattr(w, 'dnssec', None))}
        results['data'] = {k: v for k, v in results['data'].items() if v is not None}
    except Exception as e:
        results['errors'].append(f'WHOIS lookup failed: {str(e)}')
    return results