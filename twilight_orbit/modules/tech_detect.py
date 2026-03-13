import re
import httpx
from twilight_orbit.config import DEFAULT_TIMEOUT
TECH_SIGNATURES = {'headers': {'server': {'Apache': 'Apache', 'Nginx': 'nginx', 'IIS': 'Microsoft-IIS', 'LiteSpeed': 'LiteSpeed', 'Cloudflare': 'cloudflare', 'Caddy': 'Caddy', 'Gunicorn': 'gunicorn', 'Cowboy': 'Cowboy', 'Openresty': 'openresty'}, 'x-powered-by': {'PHP': 'PHP', 'ASP.NET': 'ASP\\.NET', 'Express.js': 'Express', 'Next.js': 'Next\\.js', 'Nuxt.js': 'Nuxt', 'Flask': 'Flask', 'Django': 'Django', 'Ruby on Rails': 'Phusion Passenger'}}, 'html': {'WordPress': ['wp-content', 'wp-includes', '<meta name="generator" content="WordPress'], 'Drupal': ['Drupal', 'drupal\\.js', '/sites/default/files'], 'Joomla': ['/media/jui/', '<meta name="generator" content="Joomla'], 'Shopify': ['cdn\\.shopify\\.com', 'Shopify\\.theme'], 'Wix': ['wix\\.com', 'X-Wix-'], 'Squarespace': ['squarespace', 'static\\.squarespace'], 'React': ['react', '__NEXT_DATA__', '_react'], 'Vue.js': ['vue\\.js', 'vue\\.min\\.js', '__vue__'], 'Angular': ['ng-version', 'angular', 'ng-app'], 'jQuery': ['jquery', 'jQuery'], 'Bootstrap': ['bootstrap\\.min\\.css', 'bootstrap\\.css', 'bootstrap\\.min\\.js'], 'Tailwind CSS': ['tailwindcss', 'tailwind\\.css'], 'Google Analytics': ['google-analytics\\.com', 'gtag\\(', 'GoogleAnalyticsObject'], 'Google Tag Manager': ['googletagmanager\\.com', 'gtm\\.js'], 'Cloudflare': ['cloudflare', 'cf-ray', '__cf_bm'], 'reCAPTCHA': ['recaptcha', 'google\\.com/recaptcha'], 'Font Awesome': ['font-awesome', 'fontawesome'], 'Google Fonts': ['fonts\\.googleapis\\.com', 'fonts\\.gstatic\\.com']}, 'cookies': {'PHP': 'PHPSESSID', 'ASP.NET': 'ASP\\.NET_SessionId', 'Java': 'JSESSIONID', 'Laravel': 'laravel_session', 'Django': 'csrftoken', 'Rails': '_rails_session', 'WordPress': 'wordpress_', 'Shopify': '_shopify_'}}

def run(target: str) -> dict:
    results = {'module': 'Technology Detection', 'target': target, 'technologies': [], 'categories': {'server': [], 'framework': [], 'cms': [], 'javascript': [], 'cdn': [], 'analytics': [], 'other': []}, 'errors': []}
    detected = set()
    urls = [f'https://{target}', f'http://{target}']
    for url in urls:
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=True, verify=False) as client:
                response = client.get(url)
                headers = response.headers
                body = response.text[:50000]
                cookies_str = str(response.cookies)
                for header_name, patterns in TECH_SIGNATURES['headers'].items():
                    header_value = headers.get(header_name, '')
                    for tech_name, pattern in patterns.items():
                        if re.search(pattern, header_value, re.IGNORECASE):
                            detected.add(tech_name)
                for tech_name, patterns in TECH_SIGNATURES['html'].items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            detected.add(tech_name)
                            break
                for tech_name, pattern in TECH_SIGNATURES['cookies'].items():
                    if re.search(pattern, cookies_str, re.IGNORECASE):
                        detected.add(tech_name)
                break
        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            results['errors'].append(f'Timeout connecting to {url}')
            continue
        except Exception as e:
            results['errors'].append(f'Error: {str(e)}')
            continue
    category_map = {'server': ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Caddy', 'Gunicorn', 'Cowboy', 'Openresty'], 'framework': ['PHP', 'ASP.NET', 'Express.js', 'Next.js', 'Nuxt.js', 'Flask', 'Django', 'Ruby on Rails', 'Laravel', 'Rails'], 'cms': ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Wix', 'Squarespace'], 'javascript': ['React', 'Vue.js', 'Angular', 'jQuery'], 'cdn': ['Cloudflare'], 'analytics': ['Google Analytics', 'Google Tag Manager']}
    for tech in sorted(detected):
        results['technologies'].append(tech)
        categorized = False
        for category, techs in category_map.items():
            if tech in techs:
                results['categories'][category].append(tech)
                categorized = True
                break
        if not categorized:
            results['categories']['other'].append(tech)
    return results