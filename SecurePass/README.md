# SecurePass — Password Security Analyzer

A cybersecurity dashboard-style web application that analyzes password strength in real time using rule-based security checks and pattern detection.

> **Note on the analysis approach:** SecurePass's interface is styled like a modern security dashboard, but the actual password analysis is performed by deterministic, rule-based logic (regex pattern matching and a scoring system) — not a trained machine learning model. This is stated here transparently.

## Features

- Real-time password analysis as you type, with no page reload
- Security score out of 100, with a password strength rating and risk level
- Checks for length, uppercase, lowercase, numbers, and special characters
- Detects common/weak passwords (substring matching, not just exact matches)
- Detects repeated characters (`aaaa`, `1111`, ...)
- Detects predictable sequences and keyboard-walk patterns (`1234`, `abcd`, `qwerty`, ...)
- Segmented strength meter and color-coded risk indicators
- Dynamic, itemized security signals (✓ passed / ⚠ warning) and tailored recommendations
- Show/hide password toggle
- Animated "scanning" sequence for a more deliberate analysis experience
- Fully responsive — works on desktop and mobile
- **No password is ever stored, logged, or saved anywhere** — analysis happens in memory only, per request

## Technologies Used

**Backend:** Python, Flask
**Frontend:** HTML, CSS, JavaScript (vanilla, no frameworks)
**Analysis logic:** Python `re` (regular expressions), a custom rule-based scoring system

## Project Structure

```
SentinelAI/
├── app.py                 # Flask backend + password analysis engine
├── requirements.txt
├── README.md
├── templates/
│   └── index.html         # Main page
└── static/
    ├── style.css           # Dark cybersecurity dashboard theme
    └── script.js           # Live analysis, animations, DOM updates
```

## Installation

```bash
pip install -r requirements.txt
```

## How to Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Password Analysis Criteria

| Category | What it checks | Scoring |
|---|---|---|
| Length | <6 / 6–7 / 8–11 / 12–15 / 16+ characters | Up to 35 points |
| Character variety | Uppercase, lowercase, digit, special character present | 10 points each (40 total) |
| Character diversity | Ratio of unique characters to total length | Up to 25 points |
| Common password | Substring match against known common passwords/keyboard walks | −40 point penalty |
| Repeated characters | 3+ identical characters in a row | −20 point penalty |
| Sequential pattern | 3+ character ascending/descending run, or known keyboard-row pattern | −20 point penalty |

**Final score** is clamped between 0–100 and mapped to:

| Score | Strength | Risk Level |
|---|---|---|
| 0–39 | Weak | High |
| 40–69 | Moderate | Medium |
| 70–84 | Strong | Low |
| 85–100 | Very Strong | Very Low |

## Security & Privacy Notes

- Passwords are sent over HTTPS-capable POST requests to the `/analyze` endpoint for analysis only.
- The password value is never written to a file, database, browser storage, or application log.
- Once a request finishes, the password value goes out of scope and is discarded.
- There is no user account system, login, or password history feature by design.

## Screenshots

*(Add screenshots of the app here — desktop view, mobile view, and a sample analysis result.)*
