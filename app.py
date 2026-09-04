"""
SecurePass - Password Security Analyzer
Backend: Flask app performing rule-based password complexity analysis.

IMPORTANT: No password is ever stored, logged, or written to disk.
Each password exists only in memory for the duration of a single request.
"""

import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Reference data for pattern detection
# ---------------------------------------------------------------------------

COMMON_PASSWORD_FRAGMENTS = [
    "password", "123456", "12345678", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "dragon", "football", "abc123",
    "111111", "123123", "sunshine", "princess", "login", "master",
    "hello", "freedom", "whatever", "trustno1", "passw0rd",
]

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1qaz2wsx", "qazwsx", "1q2w3e", "!qaz2wsx",
]

SEQUENTIAL_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
SEQUENTIAL_DIGITS = "0123456789"


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def check_length(password):
    """Returns (points out of 35, bucket label) for password length."""
    length = len(password)
    if length < 6:
        return 5, "high_risk"
    if length <= 7:
        return 12, "weak"
    if length <= 11:
        return 22, "moderate"
    if length <= 15:
        return 30, "strong"
    return 35, "very_strong"


def check_variety(password):
    """Returns a dict of which character classes are present, and a score out of 40."""
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=~`\[\]\\/;']", password))

    score = sum([has_upper, has_lower, has_digit, has_special]) * 10
    return {
        "upper": has_upper,
        "lower": has_lower,
        "digit": has_digit,
        "special": has_special,
    }, score


def check_diversity(password):
    """Unique-character ratio, scored out of 25. Rewards passwords that
    don't just repeat a small pool of characters."""
    if not password:
        return 0
    unique_ratio = len(set(password)) / len(password)
    return round(unique_ratio * 25)


def check_common_pattern(password):
    """Substring match against known common passwords/keyboard-walks —
    not just exact matches, since 'Password123!' should still be flagged."""
    lowered = password.lower()
    for fragment in COMMON_PASSWORD_FRAGMENTS + KEYBOARD_PATTERNS:
        if fragment in lowered:
            return True
    return False


def check_repeated_characters(password):
    """Flags 3 or more of the exact same character in a row (aaa, 111, ...)."""
    return bool(re.search(r"(.)\1{2,}", password))


def check_sequential_pattern(password):
    """Flags 3+ character runs that are consecutive ascending/descending
    letters or digits (abc, 321, ...), plus known keyboard-row walks."""
    lowered = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered:
            return True

    for seq in (SEQUENTIAL_ALPHABET, SEQUENTIAL_ALPHABET[::-1],
                SEQUENTIAL_DIGITS, SEQUENTIAL_DIGITS[::-1]):
        for i in range(len(seq) - 2):
            if seq[i:i + 3] in lowered:
                return True
    return False


# ---------------------------------------------------------------------------
# Score -> strength / risk classification
# ---------------------------------------------------------------------------

def classify(score):
    if score <= 39:
        return "WEAK", "HIGH"
    if score <= 69:
        return "MODERATE", "MEDIUM"
    if score <= 84:
        return "STRONG", "LOW"
    return "VERY STRONG", "VERY LOW"


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_password(password):
    length_score, length_bucket = check_length(password)
    variety, variety_score = check_variety(password)
    diversity_score = check_diversity(password)

    is_common = check_common_pattern(password)
    is_repeated = check_repeated_characters(password)
    is_sequential = check_sequential_pattern(password)

    positive_total = length_score + variety_score + diversity_score

    penalty = 0
    if is_common:
        penalty += 40
    if is_repeated:
        penalty += 20
    if is_sequential:
        penalty += 20

    final_score = max(0, min(100, positive_total - penalty))
    strength, risk_level = classify(final_score)

    # --- Security signals (positive + warnings) ---
    signals = []

    if length_bucket in ("strong", "very_strong"):
        signals.append({"type": "positive", "text": "Strong password length"})
    elif length_bucket == "moderate":
        signals.append({"type": "positive", "text": "Acceptable password length"})
    else:
        signals.append({"type": "warning", "text": "Password is too short"})

    signals.append({
        "type": "positive" if variety["upper"] else "warning",
        "text": "Uppercase character detected" if variety["upper"] else "Uppercase character missing",
    })
    signals.append({
        "type": "positive" if variety["lower"] else "warning",
        "text": "Lowercase character detected" if variety["lower"] else "Lowercase character missing",
    })
    signals.append({
        "type": "positive" if variety["digit"] else "warning",
        "text": "Numeric character detected" if variety["digit"] else "Numeric character missing",
    })
    signals.append({
        "type": "positive" if variety["special"] else "warning",
        "text": "Special character detected" if variety["special"] else "Special character missing",
    })

    if diversity_score >= 18:
        signals.append({"type": "positive", "text": "Good character diversity"})
    else:
        signals.append({"type": "warning", "text": "Limited character diversity"})

    if is_common:
        signals.append({"type": "warning", "text": "High-risk common password pattern detected"})
    if is_repeated:
        signals.append({"type": "warning", "text": "Repeated character pattern detected"})
    if is_sequential:
        signals.append({"type": "warning", "text": "Predictable sequential pattern detected"})

    # --- Recommendations ---
    recommendations = []
    if length_bucket in ("high_risk", "weak", "moderate"):
        recommendations.append("Increase the password length to at least 12 characters.")
    if not variety["upper"]:
        recommendations.append("Add at least one uppercase letter.")
    if not variety["lower"]:
        recommendations.append("Add at least one lowercase letter.")
    if not variety["digit"]:
        recommendations.append("Add at least one numeric character.")
    if not variety["special"]:
        recommendations.append("Add at least one special character.")
    if is_repeated:
        recommendations.append("Avoid excessive repeated characters.")
    if is_sequential:
        recommendations.append("Avoid predictable sequences (e.g. 1234, abcd, qwerty).")
    if is_common:
        recommendations.append("Avoid common passwords or well-known patterns — choose something unique.")

    if not recommendations:
        recommendations.append(
            "Good password complexity detected. Ensure the password is unique and not reused across accounts."
        )

    return {
        "score": final_score,
        "strength": strength,
        "risk_level": risk_level,
        "signals": signals,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Please enter a password to begin the security analysis."}), 400

    result = analyze_password(password)
    # 'password' goes out of scope here and is never written anywhere.
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
