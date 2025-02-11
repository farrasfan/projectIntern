from flask import request, jsonify, render_template
from config import db
import re
import string
import json
from models import Wordlist, AccessLog

def init_routes(app): 
    def save_access_log(ip, origin, response_data):
        try:
            response_json = json.dumps(response_data)
            new_log = AccessLog(ip=ip, origin=origin, respon=response_json)
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            print(f"Error saving access log: {e}")
    
    def load_wordlist():
        words = [word.word.lower() for word in Wordlist.query.all()]
        return words
    
    def check_wordlist(password):
        wordlist = load_wordlist()
        found_words = set()
        for word in wordlist:
            if re.search(rf"{re.escape(word)}", password.lower()) and word not in found_words:
                update_word_count(word)
                found_words.add(word)
                return False, word
        return True, None
    
    def update_word_count(word):
        word_entry = Wordlist.query.filter_by(word=word).first()
        if word_entry:
            word_entry.count += 1
            db.session.commit()

    def check_password_strength(password):
        errors = []

        if len(password) < 12:
            errors.append("Password should be at least 12 characters long.")
        if not re.search(r'[A-Z]', password):
            errors.append("Password should contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            errors.append("Password should contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            errors.append("Password should contain at least one number.")
        if not any(char in string.punctuation for char in password):
            errors.append("Password should contain at least one special character.")
        if re.search(r'(.)\1{3,}', password):
            errors.append("Password contains too many repeated characters.")
        if re.search(r'(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321)', password):
            errors.append("Password contains sequential numbers.")
        if errors:
            return False, errors
        return True, []

    def evaluate_password(password):
        wordlist_is_valid, restricted_word = check_wordlist(password)
        strength_is_valid, strength_errors = check_password_strength(password)

        strength_check_msg = (
            "Password is strong." 
            if strength_is_valid 
            else f"Password is weak. Issues: " + " | ".join(strength_errors)
        )
        wordlist_check_msg = (
            "Password does not contain any restricted words."
            if wordlist_is_valid
            else f"Password contains a restricted word: {restricted_word}."
        )
        is_safe = 1 if strength_is_valid and wordlist_is_valid else 0

        return {
            "strength_check": strength_check_msg,
            "wordlist_check": wordlist_check_msg,
            "is_safe": is_safe,
            "password": password,
        }

    def get_client_ip():
        # Retrieve the real IP address, considering Kong Gateway and proxies
        if request.headers.get("X-Forwarded-For"):
            return request.headers.get("X-Forwarded-For").split(',')[0]  # Take the first IP
        elif request.headers.get("X-Real-IP"):
            return request.headers.get("X-Real-IP")
        else:
            return request.remote_addr  # Fallback to default if no header found

    @app.route('/check_password', methods=['POST'])
    def check_password():
        data = request.get_json()
        password = data.get('password', '')

        ip = get_client_ip()  # Use the updated method to get the real IP
        origin = request.headers.get('Origin', 'Unknown')

        result = evaluate_password(password)
        save_access_log(ip, origin, result)

        return jsonify({"check_results": result})

    @app.route('/add_wordlist', methods=['POST'])
    def add_wordlist():
        data = request.get_json()
        new_word = data.get('word', '').lower()

        ip = get_client_ip()  # Retrieve real client IP
        origin = request.headers.get('Origin', 'Unknown')

        if not new_word:
            response = {"error": "Word is required."}
            save_access_log(ip, origin, response)  # Log access attempt
            return jsonify(response), 400

        existing_word = Wordlist.query.filter_by(word=new_word).first()

        if existing_word:
            response = {"message": "Word already exists in the wordlist."}
            save_access_log(ip, origin, response)  # Log access attempt
            return jsonify(response), 200

        new_word_entry = Wordlist(word=new_word)
        db.session.add(new_word_entry)
        db.session.commit()

        response = {"message": f"Word '{new_word}' has been added to the wordlist."}
        save_access_log(ip, origin, response)  # Log successful operation
        return jsonify(response), 201

    @app.route('/delete_wordlist', methods=['DELETE', 'POST'])
    def delete_wordlist():
        data = request.get_json()
        word_to_delete = data.get('word', '').lower()

        ip = get_client_ip()  # Retrieve real client IP
        origin = request.headers.get('Origin', 'Unknown')

        if not word_to_delete:
            response = {"error": "Word is required."}
            save_access_log(ip, origin, response)  # Log access attempt
            return jsonify(response), 400

        word_entry = Wordlist.query.filter_by(word=word_to_delete).first()

        if not word_entry:
            response = {"message": "Word does not exist in the wordlist."}
            save_access_log(ip, origin, response)  # Log access attempt
            return jsonify(response), 404

        db.session.delete(word_entry)
        db.session.commit()

        response = {"message": f"Word '{word_to_delete}' has been deleted from the wordlist."}
        save_access_log(ip, origin, response)  # Log successful operation
        return jsonify(response), 200

    @app.route('/')
    def home():
        return jsonify({"message": "Welcome to Checker Password API"})
