#!/usr/bin/env python3
import json, requests

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "sec-ch-ua-platform": '"Linux"',
    "sec-ch-ua": '"Chromium";v="149", "Not)A;Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "Origin": "https://www.betika.com",
    "Referer": "https://www.betika.com/",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
}

PAYLOAD = {
    "profile_id": "36730534",
    "stake": "1",
    "total_odd": "1.99",
    "src": "MOBILE_WEB",
    "betslip": [{
        "sub_type_id": "29",
        "bet_pick": "yes",
        "odd_value": "1.99",
        "outcome_id": "74",
        "sport_id": "14",
        "special_bet_value": "",
        "parent_match_id": "74165900",
        "bet_type": 7,
        "provider": "sr",
    }],
    "token": (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
        ".eyJpc3MiOiJodHRwOlwvXC9iZXRpa2EuY29tIiwiaWF0IjoxNzg5MDE4MjY2LCJuYmYiOjE3"
        "ODYzMzk4NjYsImV4cCI6MTc5MTYxMDI2NiwidXNlciI6eyJpZCI6IjM2NzMwNTM0IiwibW9i"
        "aWxlIjoiMjU0Nzk5NDgyNTY2IiwiYmFsYW5jZSI6IjAuMjUiLCJib251cyI6IjAuMDUiLCJw"
        "b2ludHMiOm51bGx9fQ.MLYZsz1iSkoDLvcgzJVLyBdEhh8WwL5D0WSq6ZY3X1o"
    ),
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "app_version": "6.0.0",
    "affiliate": None,
    "promo_id": None,
    "fbpid": False,
    "is_freebet": False,
}

print("POST https://api.betika.com/v2/bet")
print(json.dumps(PAYLOAD, indent=2))
print("\n" + "=" * 60)

r = requests.post("https://api.betika.com/v2/bet", headers=HEADERS, json=PAYLOAD)

print(f"Status : {r.status_code} {r.reason}")
print("Headers:")
for k, v in r.headers.items():
    print(f"  {k}: {v}")
print("\nBody:")
try:
    body = r.json()
    print(json.dumps(body, indent=2))
except Exception:
    print(r.text)
