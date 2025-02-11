import requests

def analyze_security_headers(url):
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    security_headers = {
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'Strict-Transport-Security': ['max-age'],
        'Content-Security-Policy': [],
        'X-Content-Type-Options': ['nosniff'],
        'X-XSS-Protection': ['1; mode=block', '0'],
        'Referrer-Policy': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'],
        'Permissions-Policy': []
    }

    try:
        response = requests.get(url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}

        existing_headers = {}
        missing_headers = []

        for header in security_headers:
            header_key = header.lower()
            if header_key in headers:
                existing_headers[header] = headers[header_key]
            else:
                missing_headers.append(header)

        return existing_headers, missing_headers

    except requests.RequestException as e:
        print(f"Error analyzing {url}: {e}")
        return {}, []
