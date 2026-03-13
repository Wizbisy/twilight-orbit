import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from twilight_orbit.config import TOP_PORTS, PORT_SERVICES, DEFAULT_PORT_TIMEOUT, DEFAULT_THREADS

def _scan_port(target_ip: str, port: int, timeout: float) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            service = PORT_SERVICES.get(port, 'Unknown')
            banner = _grab_banner(target_ip, port, timeout)
            return {'port': port, 'state': 'open', 'service': service, 'banner': banner}
    except Exception:
        pass
    return None

def _grab_banner(target_ip: str, port: int, timeout: float) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        sock.send(b'HEAD / HTTP/1.1\r\nHost: target\r\n\r\n')
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200] if banner else ''
    except Exception:
        return ''

def run(target: str, ports: list[int] | None=None, threads: int=DEFAULT_THREADS) -> dict:
    results = {'module': 'Port Scanner', 'target': target, 'ip': None, 'open_ports': [], 'scanned_count': 0, 'errors': []}
    scan_ports = ports or TOP_PORTS
    results['scanned_count'] = len(scan_ports)
    try:
        target_ip = socket.gethostbyname(target)
        results['ip'] = target_ip
    except socket.gaierror:
        results['errors'].append(f'Could not resolve {target} to an IP address')
        return results
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_scan_port, target_ip, port, DEFAULT_PORT_TIMEOUT): port for port in scan_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results['open_ports'].append(result)
    except Exception as e:
        results['errors'].append(f'Port scan error: {str(e)}')
    results['open_ports'].sort(key=lambda x: x['port'])
    return results