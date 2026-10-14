"""
app.py — RiskPulse
Risk-based multi-factor authentication system.
Author: heyziq05
"""

from flask import Flask, render_template, request, session, redirect, url_for
import json
import random
import time
import os
import hashlib
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
OTP_FILE = os.path.join(BASE_DIR, "otp_store.json")

app = Flask(__name__)
app.secret_key = "riskpulse-dev-key"  # In production, use a secure random key

# ─────────────────────────────────────────────
# FILE HELPERS — Load and save JSON data files
# ─────────────────────────────────────────────

def load_users():
    """Load user data from users.json"""
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    """Save updated user data back to users.json"""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def load_otp_store():
    """Load OTP records from otp_store.json"""
    with open(OTP_FILE, "r") as f:
        return json.load(f)

def save_otp_store(store):
    """Save OTP records to otp_store.json"""
    with open(OTP_FILE, "w") as f:
        json.dump(store, f, indent=2)


# ─────────────────────────────────────────────
# DEVICE FINGERPRINTING — Simulate device ID
# ─────────────────────────────────────────────

def get_device_id(request):
    """
    Create a stable device fingerprint using hashlib (consistent across restarts).
    Uses User-Agent only
    """
    user_agent = request.headers.get("User-Agent", "unknown")
    # hashlib produces the same hash every time
    stable_hash = hashlib.md5(user_agent.encode()).hexdigest()[:8]
    return "device-" + stable_hash

# ─────────────────────────────────────────────────────────────
# RISK SCORING ENGINE — Rule-Based Suspicious Detection
# ─────────────────────────────────────────────────────────────

def calculate_risk_score(username, password_correct, device_id, users):
    """
    Rule-based risk scoring engine.
    Simulates what an ML model would classify based on login behavior features.

    Features evaluated:
      1. Failed attempts  — how many times the user has failed recently
      2. Rapid attempts   — is the user trying again very quickly?
      3. Unknown device   — is this a new/unrecognized device?
      4. Unusual hour     — is the login happening at an odd time?
      5. Wrong password   — did this attempt fail authentication?

    Returns: (risk_score, risk_level, feature_flags)
    """
    score = 0
    flags = {}
    user = users.get(username, {})

    # ── Feature 1: Failed Attempts ──
    failed = user.get("failed_attempts", 0)
    flags["failed_attempts"] = failed
    if failed >= 3:
        score += 2  # High suspicion: repeated failures
        flags["failed_flag"] = True
    else:
        flags["failed_flag"] = False

    # ── Feature 2: Rapid Repeated Attempts ──
    last_attempt = user.get("last_attempt_time")
    now = time.time()
    if last_attempt and (now - float(last_attempt)) < 10:
        score += 2  # Suspicious: tried again within 10 seconds
        flags["rapid_attempt"] = True
    else:
        flags["rapid_attempt"] = False

    # ── Feature 3: Unknown Device ──
    known_devices = user.get("known_devices", [])
    if device_id not in known_devices:
        score += 1  # Mild suspicion: unrecognized device
        flags["unknown_device"] = True
    else:
        flags["unknown_device"] = False

    # ── Feature 4: Unusual Login Hour ──
    hour = datetime.now().hour
    # Consider 11 PM to 5 AM as unusual hours (23:00 – 05:00)
    if hour >= 23 or hour < 5:
        score += 1  # Mild suspicion: odd login time
        flags["unusual_hour"] = True
    else:
        flags["unusual_hour"] = False
    flags["login_hour"] = hour

    # ── Feature 5: Incorrect Password ──
    if not password_correct:
        score += 2  # Wrong password is always suspicious
        flags["wrong_password"] = True
    else:
        flags["wrong_password"] = False

    # ── Risk Classification ──
    if score >= 5:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level, flags


# ─────────────────────────────────────────────
# OTP GENERATOR — Create and store a 6-digit OTP
# ─────────────────────────────────────────────

def generate_otp(username, device_id):
    """
    Generate a 6-digit OTP, store it in otp_store.json with a timestamp,
    and print it to the terminal.
    """
    otp = str(random.randint(100000, 999999))
    store = load_otp_store()
    store[username] = {
        "otp": otp,
        "created_at": time.time()
    }
    save_otp_store(store)

    # ── Demo Output: Print OTP to terminal ──
    print("\n" + "═" * 50)
    print(f"  OTP FOR USER: {username.upper()}")
    print(f"  Code: {otp}")
    print(f"  Valid for: 1 minute")
    print(f"  Device ID: {device_id}")
    print("═" * 50 + "\n")

    return otp


def verify_otp(username, entered_otp):
    """
    Verify the OTP entered by the user.
    OTP expires after 1 minute (60 seconds).
    """
    store = load_otp_store()
    if username not in store:
        return False, "No OTP found. Please try logging in again."

    record = store[username]
    age = time.time() - float(record["created_at"])

    if age > 60:  # 1-minute expiry
        return False, "OTP has expired. Please try again."

    if record["otp"] != entered_otp.strip():
        return False, "Incorrect OTP. Please check and try again."

    # OTP is valid — remove it from store (one-time use)
    del store[username]
    save_otp_store(store)
    return True, "OTP verified successfully."


# ─────────────────────────────────────────────
# ROUTE 1: Login Page (GET + POST)
# ─────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        users = load_users()

        # ── Step 1: Check if username exists ──
        if username not in users:
            error = "Invalid username or password."
            return render_template("login.html", error=error)

        user = users[username]

        # ── Step 2: Check if account is temporarily blocked ──
        blocked_until = user.get("blocked_until")
        if blocked_until and time.time() < float(blocked_until):
            remaining = int(float(blocked_until) - time.time())
            return redirect(url_for("blocked", remaining=remaining, username=username))

        # ── Step 3: Verify password ──
        password_correct = (password == user["password"])

        # ── Step 4: Get device fingerprint ──
        device_id = get_device_id(request)
        print(f"Your device ID: {device_id}")

        # ── Step 5: Run Risk Scoring Engine ──
        score, risk_level, flags = calculate_risk_score(
            username, password_correct, device_id, users
        )

        # ── Step 6: Update attempt tracking ──
        users[username]["last_attempt_time"] = time.time()

        if not password_correct:
            # Increment failed attempts counter
            users[username]["failed_attempts"] = user.get("failed_attempts", 0) + 1
            save_users(users)
            error = "Invalid username or password."
            return render_template("login.html", error=error)

        # Password was correct — reset failed attempts
        users[username]["failed_attempts"] = 0

        # ── Step 7: Apply Mitigation Based on Risk Level ──

        if risk_level == "HIGH":
            # BLOCK: Temporary account block for 2 minutes
            users[username]["blocked_until"] = time.time() + 120  # 120 seconds
            save_users(users)
            print(f"\n[HIGH] HIGH RISK LOGIN BLOCKED for user: {username} | Score: {score}\n")
            return redirect(url_for("blocked", remaining=120, username=username))

        elif risk_level == "MEDIUM":
            # DELAY: Pause 5 seconds before allowing OTP (rate limiting simulation)
            save_users(users)
            print(f"\n[MEDIUM] MEDIUM RISK — Delaying login for user: {username} | Score: {score}\n")
            time.sleep(5)  # Artificial delay to slow down attackers

        else:
            # LOW RISK: Proceed normally
            save_users(users)
            print(f"\n[LOW] LOW RISK login for user: {username} | Score: {score}\n")

        # ── Step 8: Generate and send OTP ──
        generate_otp(username, device_id)

        # Store session data for OTP verification step
        session["username"] = username
        session["risk_level"] = risk_level
        session["risk_score"] = score
        session["flags"] = flags

        return redirect(url_for("otp_verify"))

    return render_template("login.html", error=error)


# ─────────────────────────────────────────────
# ROUTE 2: OTP Verification Page
# ─────────────────────────────────────────────

@app.route("/otp", methods=["GET", "POST"])
def otp_verify():
    # Ensure user went through login first
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    risk_level = session.get("risk_level", "LOW")
    risk_score = session.get("risk_score", 0)
    flags = session.get("flags", {})
    error = None

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        valid, message = verify_otp(username, entered_otp)

        if valid:
            # OTP correct — grant access
            session["authenticated"] = True
            return redirect(url_for("success"))
        else:
            error = message

    return render_template(
        "otp.html",
        username=username,
        risk_level=risk_level,
        risk_score=risk_score,
        flags=flags,
        error=error
    )


# ─────────────────────────────────────────────
# ROUTE 3: Blocked Account Page
# ─────────────────────────────────────────────

@app.route("/blocked")
def blocked():
    remaining = request.args.get("remaining", 120)
    username = request.args.get("username", "")
    return render_template("blocked.html", remaining=remaining, username=username)


# ─────────────────────────────────────────────
# ROUTE 4: Success / Dashboard Page
# ─────────────────────────────────────────────

@app.route("/success")
def success():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    username = session.get("username")
    risk_level = session.get("risk_level", "LOW")
    risk_score = session.get("risk_score", 0)
    flags = session.get("flags", {})

    return render_template(
        "success.html",
        username=username,
        risk_level=risk_level,
        risk_score=risk_score,
        flags=flags
    )


# ─────────────────────────────────────────────
# ROUTE 5: Logout
# ─────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# RUN APPLICATION
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  RiskPulse — Risk-Based MFA  (by heyziq05)")
    print("  Running at: http://127.0.0.1:5000")
    print("  Demo users: haziq / Haziq@1234")
    print("              bob   / Bob@5678")
    print("              admin / Admin@1234")
    print("  OTP codes will be printed here in the terminal")
    print("  Logged-in device ID will be displayed")
    print("═" * 55 + "\n")
    app.run(debug=True)
