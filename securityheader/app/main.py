from flask import Flask, request, jsonify, send_file
from checkHeader import analyze_security_headers
from checkExternal import check_external_resources
from checkWebserver import detect_webserver
from generateConfiguration import generate_apache_config, generate_nginx_openresty_config, generate_cloudflare_config
from saveConfig import save_configuration
import os
from urllib.parse import urlparse
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta
from os import environ
from pathlib import Path 

app = Flask(__name__)

# ================= PATH CONFIGURATION =================
BASE_DIR = Path(__file__).parent
CONFIG_FOLDER = BASE_DIR / "configs"
os.makedirs(CONFIG_FOLDER, exist_ok=True)

# ================= DATABASE CONFIGURATION =================
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DB_URL')

db = SQLAlchemy(app)

# ================= MODEL DATABASE =================

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    origin = db.Column(db.String(255), nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=7))).replace(tzinfo=None))

# ================= HEADER RECOMMENDATION =================
RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";',
    "X-Frame-Options": 'add_header X-Frame-Options "SAMEORIGIN";',
    "X-Content-Type-Options": 'add_header X-Content-Type-Options "nosniff";',
    "X-XSS-Protection": 'add_header X-XSS-Protection "1; mode=block";',
    "Referrer-Policy": 'add_header Referrer-Policy "strict-origin-when-cross-origin";',
    "Permissions-Policy": 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";',
    "Content-Security-Policy": 'add_header Content-Security-Policy "default-src \'self\';";'
}

# ================= LOGGING =================
def get_client_ip():
    """Retrieve the real client IP address even when behind Kong Gateway."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(',')[0]  # Take the first IP
    elif request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    else:
        return request.remote_addr  # Fallback to default if no header found

def save_access_log(ip_address, origin, response, status_code=None):
    """Log requests with IP, origin, response data, and optional status code."""
    if status_code is not None:
        response = f"Status Code: {status_code}\n{response}"

    log = AccessLog(
        ip_address=ip_address,
        origin=origin,
        response=response
    )
    db.session.add(log)
    db.session.commit()

# ================= ROUTES =================
@app.route("/")
def home():
    return jsonify({"message": "Welcome to Security Header Scanner API"})

@app.route("/scan", methods=["POST"])
def scan_website():
    try:
        ip_address = get_client_ip()
        origin = request.headers.get("Origin", "Unknown")
        data = request.json
        target_url = data.get("url")

        if not target_url:
            response = jsonify({"error": "URL is required"})
            save_access_log(ip_address, origin, response.data.decode("utf-8"), 400)
            return response, 400

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed_url = urlparse(target_url)
        subdomain = parsed_url.hostname.split(".")[0] 

        existing_headers, missing_headers = analyze_security_headers(target_url)
        missing_headers = list(missing_headers)

        external_resources = check_external_resources(target_url)
        external_resources = {key: list(value) for key, value in external_resources.items()}

        webserver = detect_webserver(target_url)

        config_content = ""
        config_filename = ""

        if webserver == "Apache":
            config_content = generate_apache_config(missing_headers, external_resources)
            config_filename = f"{subdomain}_apache.conf"
        elif webserver in ["Nginx", "OpenResty"]:
            config_content = generate_nginx_openresty_config(missing_headers, external_resources)
            config_filename = f"{subdomain}_nginx.conf"
        elif webserver == "Cloudflare":
            config_content = generate_cloudflare_config(missing_headers, external_resources)
            config_filename = f"{subdomain}_cloudflare.conf"

        if config_content:
            file_path = CONFIG_FOLDER / config_filename  
            save_configuration(config_content, file_path)

        recommended_headers_list = [RECOMMENDED_HEADERS[header] for header in missing_headers if header in RECOMMENDED_HEADERS]
        recommended_config = "server {\n  " + "\n  ".join(recommended_headers_list) + "\n}"

        response = {
            "target_url": target_url,
            "webserver": webserver,
            "existing_headers": existing_headers,
            "missing_headers": missing_headers,
            "external_resources": external_resources,
            "config_filename": config_filename,
            "download_url": f"/download/{config_filename}" if config_filename else None,
            "recommended_config": recommended_config
        }

        save_access_log(ip_address, origin, jsonify(response).data.decode("utf-8"), 200)
        return jsonify(response)
    
    except Exception as e:
        error_message = f"Internal Server Error: {str(e)}"
        response = jsonify({"error": error_message})
        save_access_log(get_client_ip(), request.headers.get("Origin", "Unknown"), error_message, 500)
        return response, 500

@app.route("/download/<filename>", methods=["GET"])
def download_config(filename):
    ip_address = get_client_ip()
    origin = request.headers.get("Origin", "Unknown")
    file_path = CONFIG_FOLDER / filename  

    if not os.path.exists(file_path):
        response = jsonify({"error": "Configuration file not found"})
        save_access_log(ip_address, origin, response.data.decode("utf-8"), 404)
        return response, 404

    save_access_log(ip_address, origin, "File downloaded successfully", 200)
    return send_file(file_path, as_attachment=True)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
