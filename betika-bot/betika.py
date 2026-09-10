#!/usr/bin/env python3
import json, sys, requests

BASE_URL = "https://api.betika.com"

TOKEN      = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJodHRwOlwvXC9iZXRpa2EuY29tIiwiaWF0IjoxNzg5MDE4MjY2LCJuYmYiOjE3"
    "ODYzMzk4NjYsImV4cCI6MTc5MTYxMDI2NiwidXNlciI6eyJpZCI6IjM2NzMwNTM0IiwibW9i"
    "aWxlIjoiMjU0Nzk5NDgyNTY2IiwiYmFsYW5jZSI6IjAuMjUiLCJib251cyI6IjAuMDUiLCJw"
    "b2ludHMiOm51bGx9fQ.MLYZsz1iSkoDLvcgzJVLyBdEhh8WwL5D0WSq6ZY3X1o"
)
PROFILE_ID = "36730534"

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://www.betika.com",
    "Referer": "https://www.betika.com/",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
}


def show_markets(data):
    meta = data.get("meta", {})
    print(f"\n  {meta.get('home_team')} vs {meta.get('away_team')}")
    print(f"  {meta.get('competition_name')} | {meta.get('start_time')}")
    print(f"  Match ID: {meta.get('parent_match_id')}\n")
    print(f"  {'sub_type_id':<14} {'Market':<40} {'Pick':<14} {'Odd':>7}  outcome_id")
    print("  " + "-" * 92)
    for mkt in data.get("data", []):
        for odd in mkt["odds"]:
            spv = f"  [{odd['special_bet_value']}]" if odd["special_bet_value"] else ""
            print(
                f"  {str(mkt['sub_type_id']):<14} {mkt['name']:<40} "
                f"{odd['display']:<14} {float(odd['odd_value']):>7.2f}  {odd['outcome_id']}{spv}"
            )


def place_bet(parent_match_id, sub_type_id, bet_pick, odd_value, outcome_id,
              stake, special_bet_value="", sport_id="14", provider="sr"):
    payload = {
        "profile_id": PROFILE_ID,
        "stake": stake,
        "total_odd": odd_value,
        "src": "MOBILE_WEB",
        "betslip": [{
            "sub_type_id": sub_type_id,
            "bet_pick": bet_pick,
            "odd_value": odd_value,
            "outcome_id": outcome_id,
            "sport_id": sport_id,
            "special_bet_value": special_bet_value,
            "parent_match_id": parent_match_id,
            "bet_type": 7,
            "provider": provider,
        }],
        "token": TOKEN,
        "user_agent": HEADERS["User-Agent"],
        "app_version": "6.0.0",
        "affiliate": None,
        "promo_id": None,
        "fbpid": False,
        "is_freebet": False,
    }
    r = requests.post(f"{BASE_URL}/v2/bet", headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()


def main():
    print("Paste odds JSON response (Ctrl+D when done):")
    raw = sys.stdin.read().strip()
    data = json.loads(raw)
    show_markets(data)

    meta           = data.get("meta", {})
    parent_match_id = str(meta.get("parent_match_id", ""))

    print("\nBet details:")
    sub_type_id = input("  sub_type_id : ").strip()
    pick        = input("  pick        : ").strip()
    stake       = input("  stake (KES) : ").strip()

    odd_value = outcome_id = special_bet_value = None
    for mkt in data.get("data", []):
        if str(mkt["sub_type_id"]) == sub_type_id:
            for odd in mkt["odds"]:
                if odd["display"].lower() == pick.lower():
                    odd_value         = odd["odd_value"]
                    outcome_id        = str(odd["outcome_id"])
                    special_bet_value = odd["special_bet_value"] or ""
                    break

    if not odd_value:
        print(f"\nPick '{pick}' not found in sub_type_id {sub_type_id}.")
        sys.exit(1)

    print(f"\n  {pick} @ {odd_value} | stake KES {stake}")
    if input("  Confirm? [y/N] ").strip().lower() != "y":
        print("Aborted.")
        return

    result = place_bet(
        parent_match_id=parent_match_id,
        sub_type_id=sub_type_id,
        bet_pick=pick.lower(),
        odd_value=odd_value,
        outcome_id=outcome_id,
        stake=stake,
        special_bet_value=special_bet_value,
    )
    print(f"\n  {result.get('message', json.dumps(result, indent=2))}")


if __name__ == "__main__":
    main()
