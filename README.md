# RiskPulse

> Risk-based multi-factor authentication. Rule-based risk scoring detects suspicious logins and enforces OTP verification.
>
> Author: **heyziq05**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Folder Structure](#folder-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [Demo Credentials](#demo-credentials)
- [How It Works](#how-it-works)
- [Risk Scoring System](#risk-scoring-system)
- [Mitigation Responses](#mitigation-responses)
- [Managing Users](#managing-users)
- [Trusting a Device](#trusting-a-device)
- [Resetting a Blocked Account](#resetting-a-blocked-account)
- [Common Errors](#common-errors)
- [File Reference](#file-reference)

---

## Overview

This system authenticates users through a **three-stage pipeline**:

```
Stage 1            Stage 2                    Stage 3
─────────          ──────────────────         ──────────────
Username     →     Risk Scoring          →    OTP Verification
+ Password         (5 features scored)        (6-digit code)
```

After the password is verified, the system evaluates login behaviour using a rule-based risk engine and decides whether to allow, delay, or block the login attempt before proceeding to OTP.

---

## Features

- Username and password authentication
- Rule-based risk scoring engine (5 features)
- Three risk levels: LOW, MEDIUM, HIGH
- OTP-based Multi-Factor Authentication
- Automatic 5-second delay for medium-risk logins
- Temporary 120-second account block for high-risk logins
- Device fingerprinting using User-Agent hash
- Live countdown timer on blocked page
- Risk score and feature flags displayed on OTP and success pages
- OTP printed to terminal for demo purposes

---

## Folder Structure

```
src/
├── app.py              ← Main Flask application (all logic lives here)
├── users.json          ← User database (credentials + device list)
├── otp_store.json      ← Temporary OTP storage (auto-managed)
├── templates/
│   ├── login.html      ← Step 1: Login form
│   ├── otp.html        ← Step 2: OTP entry + risk report
│   ├── blocked.html    ← High-risk block page with countdown
│   └── success.html    ← Authenticated dashboard
└── static/
    └── style.css       ← Dark cybersecurity UI stylesheet
```

> The `templates/` folder **must** be inside the same folder as `app.py`. If it is placed anywhere else, Flask will throw a `TemplateNotFound` error.

---

## Requirements

- Python 3.8 or higher
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

**Python packages required:**

| Package | Purpose |
|---------|---------|
| `flask` | Web framework |

All other modules used (`json`, `random`, `time`, `hashlib`, `datetime`) are part of Python's standard library and require no installation.

---

## Installation

**Step 1 — Clone or download the project**

If you downloaded a zip file, extract it. Your folder should look like the structure shown above.

**Step 2 — Open a terminal in the project folder**

On Windows:
```
cd C:\path\to\your\project
```

On Mac/Linux:
```bash
cd /path/to/your/project
```

**Step 3 — Install Flask**

```bash
pip install flask
```

That is the only package you need to install.

---

## Running the App

From inside the project folder, run:

```bash
python app.py
```

You should see this output in the terminal:

```
═══════════════════════════════════════════════════════
  RiskPulse — Risk-Based MFA  (by heyziq05)
  Running at: http://127.0.0.1:5000
  Demo users: haziq / Haziq@1234
              bob   / Bob@5678
              admin / Admin@1234
  OTP codes will be printed here in the terminal
  Logged-in device ID will be displayed
═══════════════════════════════════════════════════════
```

Open your browser and go to:

```
http://127.0.0.1:5000
```

> **Important:** Keep the terminal window open while using the app. OTP codes are printed here. Do not close it during a demo.

To stop the server, press `Ctrl + C` in the terminal.

---

## Demo Credentials

Three test accounts are pre-loaded in `users.json`:

| Username | Password     | Known Devices |
|----------|-------------|---------------|
| haziq    | Haziq@1234  | device-90daa551 |
| bob      | Bob@5678    | None by default |
| admin    | Admin@1234  | None by default |

> If no devices are trusted by default, the **unknown device** flag (+1 point) will always be active on first use. See [Trusting a Device](#trusting-a-device) to fix this.

---

## How It Works

### Login Flow

```
User submits username + password
           │
           ▼
   Is account blocked?  ──YES──▶  Redirect to blocked page (countdown)
           │
          NO
           │
           ▼
  Does username exist?  ──NO───▶  Show "Invalid credentials" error
           │
          YES
           │
           ▼
   Run Risk Scoring Engine
   (extract 5 features, calculate score)
           │
           ├── Score ≥ 5 (HIGH)    ──▶  Block account 120s
           │
           ├── Score 3–4 (MEDIUM)  ──▶  Wait 5 seconds, then OTP page
           │
           └── Score 0–2 (LOW)     ──▶  OTP page immediately
                       │
                       ▼
             User enters 6-digit OTP
                       │
              ┌────────┴────────┐
            Correct           Wrong
              │                  │
              ▼                  ▼
        Access Granted      Show error, try again
```

### OTP Flow

When the OTP page loads:
1. A 6-digit code is generated and saved to `otp_store.json`
2. The code is **printed in the terminal** (simulating email/SMS delivery)
3. The user has **5 minutes** to enter the correct code
4. After a correct entry, the OTP is deleted (single-use)

---

## Risk Scoring System

The risk engine evaluates 5 behavioural features and assigns points:

| Feature | Condition | Points |
|---------|-----------|--------|
| Failed Attempts | 3 or more previous failures | +2 |
| Rapid Attempt | Retry within 10 seconds | +2 |
| Unknown Device | Device not in trusted list | +1 |
| Unusual Hour | Login between 11 PM and 5 AM | +1 |
| Wrong Password | Incorrect password submitted | +2 |

**Maximum possible score: 8 points**

### Risk Classification

| Total Score | Risk Level | Response |
|-------------|------------|----------|
| 0 – 2 | LOW | Standard OTP verification |
| 3 – 4 | MEDIUM | 5-second delay + OTP verification |
| 5+ | HIGH | Account blocked for 120 seconds |

### Example Scenarios

**Scenario A — Normal login (LOW)**
```
Correct password    → 0 pts
Known device        → 0 pts
Normal hour         → 0 pts
No rapid attempt    → 0 pts
────────────────────────────
Total: 0 pts → LOW
```

**Scenario B — Suspicious login (MEDIUM)**
```
Correct password    → 0 pts
Unknown device      → +1 pt
Unusual hour        → +1 pt
1 prior failure     → 0 pts
────────────────────────────
Total: 2 pts → LOW (borderline)
```

**Scenario C — Attack pattern (HIGH)**
```
Wrong password      → +2 pts
3+ prior failures   → +2 pts
Rapid retry         → +2 pts
────────────────────────────
Total: 6 pts → HIGH
```

---

## Mitigation Responses

### LOW Risk — Standard OTP
The user proceeds directly to the OTP page with no delay. This is the normal login experience for legitimate users.

### MEDIUM Risk — Login Delay
The server pauses for 5 seconds before showing the OTP page. The browser appears to be loading. This rate-limits automated attack scripts from trying many passwords quickly.

```
Without delay:  ~1000 attempts/minute
With 5s delay:  ~12 attempts/minute
```

### HIGH Risk — Account Block
The account is locked for 120 seconds. A countdown timer is displayed. Every login attempt during this period is rejected immediately, regardless of whether the password is correct.

The block is stored as a timestamp in `users.json`:
```json
"blocked_until": 1716000220.0
```

When the timestamp passes, the block automatically expires — no manual action needed.

---

## Managing Users

### Adding a New User

Open `users.json` and add a new entry following this exact format:

```json
{
  "haziq": {
    "password": "Haziq@1234",
    "known_devices": ["device-90daa551"],
    "blocked_until": null,
    "failed_attempts": 0,
    "last_attempt_time": null
  },
  "newuser": {
    "password": "NewUser@2024",
    "known_devices": [],
    "blocked_until": null,
    "failed_attempts": 0,
    "last_attempt_time": null
  }
}
```

> Usernames must be **lowercase**. The app converts all input to lowercase before checking.

### Changing a Password

Find the user in `users.json` and update the `password` field:

```json
"password": "YourNewPassword@123"
```

Save the file. Changes take effect immediately — no restart needed.

### Removing a User

Delete the entire block for that user from `users.json`, making sure the remaining JSON stays valid (check commas between entries).

---

## Trusting a Device

By default, all devices are unknown (+1 risk point). To mark your device as trusted:

**Step 1** — Login and check terminal for OTP request and device-ID:

```
  Device ID: device-a3f8c21b
```

**Step 2** — Copy the device ID and add it to `users.json` for the relevant user:

```json
"known_devices": ["device-a3f8c21b"]
```

**Step 3** — Restart the server.

That device will now be treated as trusted and will not add to the risk score.

> To trust the same device for multiple users, add the device ID to each user's `known_devices` list.

---

## Resetting a Blocked Account

If an account gets blocked during testing and you do not want to wait 120 seconds, open `users.json` and reset these three fields:

```json
"blocked_until": null,
"failed_attempts": 0,
"last_attempt_time": null
```

Save the file. The block is lifted immediately — no server restart required.

---

## Common Errors

### `TemplateNotFound: login.html`

**Cause:** The `templates/` folder is not in the same directory as `app.py`.

**Fix:** Make sure your folder structure looks exactly like this:

```
your-project-folder/
├── app.py
├── users.json
├── otp_store.json
├── templates/          ← must be here, next to app.py
│   ├── login.html
│   ├── otp.html
│   ├── blocked.html
│   └── success.html
└── static/
    └── style.css
```

---

### `ModuleNotFoundError: No module named 'flask'`

**Fix:**
```bash
pip install flask
```

---

### OTP expired before I could enter it

OTPs are valid for **1 minute**. If it expires, simply go back to the login page and log in again to generate a new one.

---

### Port 5000 already in use

```
OSError: [Errno 48] Address already in use
```

**Fix:** Either stop the other process using port 5000, or change the port in `app.py`:

```python
app.run(debug=True, port=5001)
```

Then open `http://127.0.0.1:5001` instead.

---

## File Reference

| File | Description |
|------|-------------|
| `app.py` | Main Flask application. All routes, risk scoring engine, OTP logic, and mitigation responses. |
| `users.json` | User database. Edit this to add/change users, trust devices, or reset blocks. |
| `otp_store.json` | Temporary OTP storage. Managed automatically — do not edit manually. |
| `templates/login.html` | Login form (Step 1 of authentication). |
| `templates/otp.html` | OTP entry form with live risk score display (Step 2 of authentication). |
| `templates/blocked.html` | Displayed when a HIGH risk login is detected. Shows countdown timer. |
| `templates/success.html` | Final page after successful authentication. Shows full risk report. |
| `static/style.css` | CSS stylesheet for all pages. |

---

## Important Notes

- This system uses `debug=True` which is suitable for **local development only**. Never deploy with debug mode enabled on a public server.
- The `app.secret_key` should be changed to a long, random string for any non-demo use.
- OTP codes are printed to the terminal instead of sent by email/SMS. This is intentional for demo purposes.
- The risk scoring engine is rule-based, not a trained ML model. It demonstrates the same concepts (feature extraction, classification, automated response) that a real ML system would use.

---

*RiskPulse · © heyziq05*
