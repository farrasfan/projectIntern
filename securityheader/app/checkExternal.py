import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import os

resource_types = {
    'img-src': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.ico'],
    'media-src': ['.mp4', '.webm', '.ogv', '.avi', '.mov', '.flv', '.mkv', '.mp3', '.wav', '.ogg', '.aac', '.flac'],
    'script-src': ['.js', '.mjs', '.cjs'],
    'style-src': ['.css'],
    'font-src': ['.woff', '.woff2', '.ttf', '.otf', '.eot'],
    'object-src': ['.swf', '.jar'],
    'frame-src': [],
    'connect-src': ['.json', '.xml', '.csv'],
    'form-action': []
}

def is_external(url, base_url):
    parsed_base = urlparse(base_url)
    parsed_url = urlparse(url)
    return parsed_url.netloc and parsed_url.netloc != parsed_base.netloc

def categorize_resource(url):
    ext = os.path.splitext(url)[1].lower()
    if 'fonts.googleapis.com/css' in url:
        return 'style-src'
    for directive, extensions in resource_types.items():
        if ext in extensions or directive in ['frame-src', 'form-action']:
            return directive
    return None

def check_external_resources(base_url):
    all_detected_resources = defaultdict(set)

    try:
        response = requests.get(base_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)

        for link in links:
            path = link['href']
            full_url = urljoin(base_url, path)
            if full_url.startswith(base_url):
                try:
                    resp = requests.get(full_url)
                    soup = BeautifulSoup(resp.text, 'html.parser')

                    for tag in soup.find_all(['script', 'link', 'img', 'iframe', 'style', 'object', 'embed', 'source', 'video', 'audio', 'form']):
                        resource_url = tag.get('href') or tag.get('src') or tag.get('action')
                        if resource_url:
                            full_resource_url = urljoin(full_url, resource_url)
                            if is_external(full_resource_url, base_url):
                                directive = categorize_resource(full_resource_url)
                                if directive:
                                    all_detected_resources[directive].add(full_resource_url)

                except requests.RequestException:
                    pass

    except requests.RequestException:
        pass

    return all_detected_resources
