import dns.resolver
from twilight_orbit.config import DNS_RECORD_TYPES, DEFAULT_DNS_TIMEOUT

def run(target: str) -> dict:
    results = {'module': 'DNS Lookup', 'target': target, 'records': {}, 'errors': []}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']
    resolver.timeout = DEFAULT_DNS_TIMEOUT
    resolver.lifetime = DEFAULT_DNS_TIMEOUT
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(target, record_type)
            records = []
            for rdata in answers:
                if record_type == 'MX':
                    records.append({'priority': rdata.preference, 'exchange': str(rdata.exchange)})
                elif record_type == 'SOA':
                    records.append({'mname': str(rdata.mname), 'rname': str(rdata.rname), 'serial': rdata.serial, 'refresh': rdata.refresh, 'retry': rdata.retry, 'expire': rdata.expire, 'minimum': rdata.minimum})
                else:
                    records.append(str(rdata))
            if records:
                results['records'][record_type] = records
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            results['errors'].append(f'Domain {target} does not exist')
            break
        except dns.resolver.NoNameservers:
            results['errors'].append(f'No nameservers available for {target}')
            break
        except dns.exception.Timeout:
            results['errors'].append(f'Timeout querying {record_type} records')
        except Exception as e:
            results['errors'].append(f'Error querying {record_type}: {str(e)}')
    return results