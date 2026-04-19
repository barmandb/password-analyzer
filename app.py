from flask import Flask, render_template, request, jsonify
import re
import math
import random
import string
import hashlib
import requests

app = Flask(__name__)


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password123", "111111", "123123", "admin", "letmein"
}


def estimate_crack_time(password: str) -> str:
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0 or len(password) == 0:
        return "Instantly"

    combinations = charset ** len(password)
    guesses_per_second = 10_000_000_000
    seconds = combinations / guesses_per_second

    if seconds < 1:
        return "Less than a second"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    if seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    if seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    if seconds < 31536000 * 100:
        return f"{int(seconds / 31536000)} years"

    return "Centuries"


def detect_patterns(password: str) -> list[str]:
    issues = []
    lower_pw = password.lower()

    if lower_pw in COMMON_PASSWORDS:
        issues.append("This password is very common.")

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated characters.")

    sequential_patterns = [
        "1234", "2345", "3456", "4567", "5678", "6789",
        "abcd", "bcde", "cdef", "qwer", "asdf", "zxcv"
    ]
    for pattern in sequential_patterns:
        if pattern in lower_pw:
            issues.append("Contains predictable sequential pattern.")
            break

    if len(password) < 8:
        issues.append("Password is too short.")

    return issues


def get_suggestions(password: str) -> list[str]:
    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        suggestions.append("Add symbols like @, #, $, !.")
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("Avoid common passwords.")
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("Avoid repeated characters.")
    if not suggestions:
        suggestions.append("This password already follows good basic practices.")

    return suggestions


def calculate_strength(password: str) -> tuple[int, str]:
    score = 0

    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if re.search(r"[a-z]", password):
        score += 15
    if re.search(r"[A-Z]", password):
        score += 15
    if re.search(r"[0-9]", password):
        score += 15
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15

    pattern_issues = detect_patterns(password)
    score -= min(len(pattern_issues) * 10, 30)

    score = max(0, min(score, 100))

    if score < 40:
        label = "Weak"
    elif score < 70:
        label = "Medium"
    else:
        label = "Strong"

    return score, label


def check_pwned(password: str) -> dict:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10
        )
        response.raise_for_status()

        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {
                    "found": True,
                    "count": int(count)
                }

        return {
            "found": False,
            "count": 0
        }

    except requests.RequestException:
        return {
            "found": None,
            "count": 0
        }


def generate_secure_password(length: int = 16) -> str:
    if length < 12:
        length = 12

    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    symbol = random.choice("!@#$%^&*()-_=+[]{};:,.?/")

    remaining_length = length - 4
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    remaining = "".join(random.choice(all_chars) for _ in range(remaining_length))

    password_list = list(lowercase + uppercase + digit + symbol + remaining)
    random.shuffle(password_list)
    return "".join(password_list)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    password = request.form.get("password", "")

    if not password:
        return jsonify({"error": "Please enter a password."}), 400

    score, label = calculate_strength(password)
    issues = detect_patterns(password)
    suggestions = get_suggestions(password)
    crack_time = estimate_crack_time(password)
    breach_data = check_pwned(password)

    return jsonify({
        "score": score,
        "label": label,
        "issues": issues,
        "suggestions": suggestions,
        "crack_time": crack_time,
        "breach_found": breach_data["found"],
        "breach_count": breach_data["count"]
    })


@app.route("/generate", methods=["GET"])
def generate():
    password = generate_secure_password()
    return jsonify({"password": password})


if __name__ == "__main__":
    app.run(debug=True, port=5002)