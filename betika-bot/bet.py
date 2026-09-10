#!/usr/bin/env python3
"""
Usage:
    python bet.py                    # uses DEFAULT_MATCH_ID
    python bet.py 74165900           # specify match id
"""
import json, sys, requests

TOKEN      = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJodHRwOlwvXC9iZXRpa2EuY29tIiwiaWF0IjoxNzg5MDE4MjY2LCJuYmYiOjE3"
    "ODYzMzk4NjYsImV4cCI6MTc5MTYxMDI2NiwidXNlciI6eyJpZCI6IjM2NzMwNTM0IiwibW9i"
    "aWxlIjoiMjU0Nzk5NDgyNTY2IiwiYmFsYW5jZSI6IjAuMjUiLCJib251cyI6IjAuMDUiLCJw"
    "b2ludHMiOm51bGx9fQ.MLYZsz1iSkoDLvcgzJVLyBdEhh8WwL5D0WSq6ZY3X1o"
)
PROFILE_ID      = "36730534"
DEFAULT_MATCH   = "74165900"
ODDS_URL        = "https://api.betika.com/v1/uo/match"
BET_URL         = "https://api.betika.com/v2/bet"

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://www.betika.com",
    "Referer": "https://www.betika.com/",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
}

SEP  = "=" * 72
SEP2 = "-" * 72


def fetch_odds(match_id):
    print(f"\n  GET {ODDS_URL}?parent_match_id={match_id}")
    r = requests.get(ODDS_URL, headers=HEADERS, params={"parent_match_id": match_id})
    print(f"  Status: {r.status_code} {r.reason}")
    r.raise_for_status()
    return r.json()


def show_markets(data):
    meta = data.get("meta", {})
    print(f"\n{SEP}")
    print(f"  {meta.get('home_team')} vs {meta.get('away_team')}")
    print(f"  {meta.get('competition_name')} | {meta.get('start_time')}")
    print(f"  Match ID: {meta.get('parent_match_id')}")
    print(f"{SEP}")
    print(f"  {'sub_type_id':<14} {'Market':<38} {'Pick':<18} {'Odd':>7}  outcome_id")
    print(f"  {SEP2}")
    for mkt in data.get("data", []):
        for odd in mkt["odds"]:
            spv = f" [{odd['special_bet_value']}]" if odd["special_bet_value"] else ""
            print(
                f"  {str(mkt['sub_type_id']):<14} {mkt['name']:<38} "
                f"{odd['display']:<18} {float(odd['odd_value']):>7.2f}  {odd['outcome_id']}{spv}"
            )


def resolve_pick(data, sub_type_id, pick):
    for mkt in data.get("data", []):
        if str(mkt["sub_type_id"]) == sub_type_id:
            for odd in mkt["odds"]:
                if odd["display"].lower() == pick.lower():
                    return odd["odd_value"], str(odd["outcome_id"]), odd["special_bet_value"] or ""
    return None, None, None


def build_payload(match_id, sub_type_id, bet_pick, odd_value, outcome_id, stake, special_bet_value=""):
    return {
        "profile_id": PROFILE_ID,
        "stake": stake,
        "total_odd": odd_value,
        "src": "MOBILE_WEB",
        "betslip": [{
            "sub_type_id": sub_type_id,
            "bet_pick": bet_pick,
            "odd_value": odd_value,
            "outcome_id": outcome_id,
            "sport_id": "14",
            "special_bet_value": special_bet_value,
            "parent_match_id": match_id,
            "bet_type": 7,
            "provider": "sr",
        }],
        "token": TOKEN,
        "user_agent": HEADERS["User-Agent"],
        "app_version": "6.0.0",
        "affiliate": None,
        "promo_id": None,
        "fbpid": False,
        "is_freebet": False,
    }


def main():
    match_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MATCH

    # 1. Fetch odds
    print(f"\n{SEP}")
    print(f"  FETCHING ODDS  —  match {match_id}")
    print(f"{SEP}")
    data = fetch_odds(match_id)
    meta = data.get("meta", {})
    parent_match_id = str(meta.get("parent_match_id", match_id))

    # 2. Display market table
    show_markets(data)

    # 3. Prompt selection
    print(f"\n{SEP}")
    print(f"  BET SELECTION")
    print(f"{SEP}")
    sub_type_id = input("  sub_type_id : ").strip()
    pick        = input("  pick        : ").strip()
    stake       = input("  stake (KES) : ").strip()

    # 4. Resolve odd_value / outcome_id
    odd_value, outcome_id, special_bet_value = resolve_pick(data, sub_type_id, pick)
    if not odd_value:
        print(f"\n  [ERROR] '{pick}' not found in sub_type_id {sub_type_id}")
        sys.exit(1)

    payload = build_payload(
        match_id=parent_match_id,
        sub_type_id=sub_type_id,
        bet_pick=pick.lower(),
        odd_value=odd_value,
        outcome_id=outcome_id,
        stake=stake,
        special_bet_value=special_bet_value,
    )

    # 5. Show full request
    print(f"\n{SEP}")
    print(f"  REQUEST  →  POST /v2/bet")
    print(f"{SEP}")
    print(json.dumps(payload, indent=2))

    # 6. Confirm
    print(f"\n  {pick} @ {odd_value} | stake KES {stake}")
    if input(f"\n  Confirm? [y/N] ").strip().lower() != "y":
        print("  Aborted.")
        return

    # 7. Place bet + show full response
    print(f"\n{SEP}")
    print(f"  RESPONSE  ←  api.betika.com")
    print(f"{SEP}")
    resp = requests.post(BET_URL, headers=HEADERS, json=payload)
    print(f"  Status  : {resp.status_code} {resp.reason}")
    print(f"  Headers :")
    for k, v in resp.headers.items():
        print(f"    {k}: {v}")
    print(f"\n  Body    :")
    try:
        body = resp.json()
        print(json.dumps(body, indent=2))
        msg = body.get("message", "")
        if msg:
            print(f"\n  {SEP2}")
            print(f"  {msg}")
    except Exception:
        print(resp.text)


if __name__ == "__main__":
    main()
