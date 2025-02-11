import requests

def detect_webserver(url):
    try:
        response = requests.get(url, timeout=10)
        server_header = response.headers.get('Server', '').lower()

        if "apache" in server_header:
            return "Apache"
        elif "nginx" in server_header:
            return "Nginx"
        elif "openresty" in server_header:
            return "OpenResty"
        elif "cloudflare" in server_header:
            return "Cloudflare"
        else:
            return "Unknown"

    except requests.RequestException:
        return "Unknown"
