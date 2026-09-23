"""Render dist/telemetry.svg from the GitHub GraphQL API.

Usage: GITHUB_TOKEN=... python telemetry.py <login> [--mock]
"""
import datetime as dt
import json
import os
import sys
import urllib.request
from collections import Counter
from html import escape

QUERY = """
query($login: String!) {
  user(login: $login) {
    followers { totalCount }
    repositories(ownerAffiliations: OWNER, first: 100, privacy: PUBLIC) {
      totalCount
      nodes {
        stargazerCount
        isFork
        languages(first: 6, orderBy: {field: SIZE, direction: DESC}) {
          edges { size node { name color } }
        }
      }
    }
    contributionsCollection {
      restrictedContributionsCount
      contributionCalendar {
        totalContributions
        weeks { contributionDays { date contributionCount } }
      }
    }
  }
}
"""


def fetch(login):
    req = urllib.request.Request(
        "https://api.github.com/graphql",
        data=json.dumps({"query": QUERY, "variables": {"login": login}}).encode(),
        headers={"Authorization": f"bearer {os.environ['GITHUB_TOKEN']}"},
    )
    with urllib.request.urlopen(req) as r:
        body = json.load(r)
    if "errors" in body:
        raise SystemExit(body["errors"])
    return body["data"]["user"]


def mock():
    import random
    random.seed(7)
    start = dt.date.today() - dt.timedelta(days=364)
    days = [{"date": str(start + dt.timedelta(d)),
             "contributionCount": random.choice([0, 0, 0, 1, 2, 4, 7])} for d in range(365)]
    weeks = [{"contributionDays": days[i:i + 7]} for i in range(0, 365, 7)]
    langs = [("Python", "#3572A5", 9000), ("HTML", "#e34c26", 5000),
             ("Jupyter Notebook", "#DA5B0B", 3000), ("Shell", "#89e051", 800)]
    return {
        "followers": {"totalCount": 12},
        "repositories": {"totalCount": 6, "nodes": [{
            "stargazerCount": 1, "isFork": False,
            "languages": {"edges": [{"size": s, "node": {"name": n, "color": c}} for n, c, s in langs]}}]},
        "contributionsCollection": {"restrictedContributionsCount": 40, "contributionCalendar": {
            "totalContributions": sum(d["contributionCount"] for d in days), "weeks": weeks}},
    }


def streaks(days):
    counts = [d["contributionCount"] for d in days]
    longest = run = 0
    for c in counts:
        run = run + 1 if c else 0
        longest = max(longest, run)
    current = 0
    tail = counts[:-1] if counts and counts[-1] == 0 else counts  # today may still be empty
    for c in reversed(tail):
        if not c:
            break
        current += 1
    return current, longest


def render(u):
    cal = u["contributionsCollection"]["contributionCalendar"]
    private = u["contributionsCollection"].get("restrictedContributionsCount", 0)
    days = [d for w in cal["weeks"] for d in w["contributionDays"]]
    weekly = [sum(d["contributionCount"] for d in w["contributionDays"]) for w in cal["weeks"]][-52:]
    current, longest = streaks(days)
    active = sum(1 for d in days if d["contributionCount"])
    best = max(days, key=lambda d: d["contributionCount"])
    best_date = dt.date.fromisoformat(best["date"]).strftime("%b %d")

    repos = u["repositories"]["nodes"]
    stars = sum(r["stargazerCount"] for r in repos)
    lang_size, lang_color = Counter(), {}
    for r in repos:
        if r["isFork"]:
            continue
        for e in r["languages"]["edges"]:
            lang_size[e["node"]["name"]] += e["size"]
            lang_color[e["node"]["name"]] = e["node"]["color"] or "#8b949e"
    top = lang_size.most_common(4)
    total_lang = sum(s for _, s in top) or 1

    rows = [
        ("contributions", f"{cal['totalContributions'] + private}",
         f"last 365d · {private} private" if private else "last 365d"),
        ("current streak", f"{current}d", "keep the shell alive"),
        ("longest streak", f"{longest}d", ""),
        ("active days", f"{active}", f"{active * 100 // max(len(days), 1)}% uptime"),
        ("peak day", f"{best['contributionCount']}", best_date),
        ("public repos", f"{u['repositories']['totalCount']}", f"★ {stars}"),
        ("followers", f"{u['followers']['totalCount']}", "crew"),
    ]

    out = []
    a = out.append
    W, H = 860, 352
    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="pinsql telemetry">')
    a("""<style>
.t{font:14px 'Fira Code','JetBrains Mono',Consolas,monospace;fill:#c9d1d9;white-space:pre}
.m{fill:#00ff9f}.c{fill:#00e5ff}.d{fill:#6e7681}.r{fill:#ff2e63}.k{fill:#00ff9f;font-weight:700}.sm{font-size:12px}.b{font-weight:700;fill:#e6edf3}
.l{opacity:0;animation:in .3s ease forwards}
.bar{transform-box:fill-box;transform-origin:bottom;transform:scaleY(0);animation:grow .6s cubic-bezier(.2,.8,.2,1) forwards}
.seg{transform-box:fill-box;transform-origin:left;transform:scaleX(0);animation:sx .8s ease forwards 2.2s}
.cur{animation:bl 1s steps(1) infinite}
@keyframes in{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
@keyframes grow{to{transform:scaleY(1)}}
@keyframes sx{to{transform:scaleX(1)}}
@keyframes bl{50%{opacity:0}}
</style>""")
    a('<defs><linearGradient id="glow" x1="0" x2="1"><stop offset="0" stop-color="#00ff9f"/><stop offset="1" stop-color="#00e5ff"/></linearGradient>'
      '<linearGradient id="bg" x1="0" y1="1" x2="0" y2="0"><stop offset="0" stop-color="#00ff9f" stop-opacity=".35"/><stop offset="1" stop-color="#00e5ff"/></linearGradient></defs>')
    a(f'<rect width="{W}" height="{H}" rx="12" fill="#0d1117"/><rect x=".5" y=".5" width="{W-1}" height="{H-1}" rx="12" fill="none" stroke="#30363d"/>')
    a(f'<rect x="1" y="1" width="{W-2}" height="34" rx="11" fill="#161b22"/><rect x="1" y="20" width="{W-2}" height="14" fill="#161b22"/>')
    a('<circle cx="22" cy="17" r="6" fill="#ff5f56"/><circle cx="42" cy="17" r="6" fill="#ffbd2e"/><circle cx="62" cy="17" r="6" fill="#27c93f"/>')
    a(f'<text x="{W//2}" y="22" text-anchor="middle" class="t d sm">root@pinsql: ~ — telemetry</text>')
    a(f'<rect y="34" width="{W}" height="2" fill="url(#glow)"/>')
    a('<text x="24" y="66" class="t l" style="animation-delay:.1s"><tspan class="m">root@pinsql</tspan><tspan class="d">:</tspan>'
      '<tspan class="c">~</tspan><tspan class="d">$ </tspan>./telemetry --window 365d</text>')

    # left: key/value readout
    for i, (k, v, note) in enumerate(rows):
        y = 104 + i * 26
        a(f'<text x="24" y="{y}" class="t l" style="animation-delay:{.4 + i * .15:.2f}s">'
          f'<tspan class="k">{escape(k):<15}</tspan><tspan class="b">{escape(v):>6}</tspan>'
          f'<tspan class="d">  {escape(note)}</tspan></text>')

    # right: weekly contributions bars
    x0, y_base, cw, ch = 440, 250, 396, 150
    a(f'<text x="{x0}" y="96" class="t d sm l" style="animation-delay:.4s">commits / week · 52w</text>')
    peak = max(weekly) or 1
    a(f'<text x="{x0 + cw}" y="96" text-anchor="end" class="t r sm l" style="animation-delay:.4s">peak {peak}</text>')
    for g in (0.25, 0.5, 0.75):
        a(f'<rect x="{x0}" y="{y_base - ch * g:.1f}" width="{cw}" height="1" fill="#21262d"/>')
    a(f'<rect x="{x0}" y="{y_base}" width="{cw}" height="1" fill="#30363d"/>')
    step = cw / max(len(weekly), 1)
    for i, c in enumerate(weekly):
        h = max(2, ch * c / peak) if c else 2
        fill = "url(#bg)" if c else "#21262d"
        a(f'<rect class="bar" style="animation-delay:{.6 + i * .025:.3f}s" x="{x0 + i * step + 1:.1f}" y="{y_base - h:.1f}" '
          f'width="{step - 2:.1f}" height="{h:.1f}" rx="1.5" fill="{fill}"/>')

    # bottom: language split
    ly = 312
    a(f'<text x="24" y="{ly - 10}" class="t d sm l" style="animation-delay:2s">lang split</text>')
    x = 24.0
    bw = W - 48
    for i, (name, size) in enumerate(top):
        w = bw * size / total_lang
        a(f'<rect class="seg" x="{x:.1f}" y="{ly - 4}" width="{max(w - 2, 1):.1f}" height="8" rx="4" fill="{lang_color[name]}"/>')
        x += w
    lx = 24
    for i, (name, size) in enumerate(top):
        label = f"{name} {size * 100 / total_lang:.0f}%"
        a(f'<circle cx="{lx + 5}" cy="{ly + 20}" r="5" fill="{lang_color[name]}" class="l" style="animation-delay:2.6s"/>'
          f'<text x="{lx + 16}" y="{ly + 25}" class="t sm l" style="animation-delay:2.6s">{escape(label)}</text>')
        lx += 16 + len(label) * 7.4 + 26

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    a(f'<text x="{W - 24}" y="{ly + 25}" text-anchor="end" class="t d sm">sync {stamp} <tspan class="m cur">█</tspan></text>')
    a("</svg>")
    return "\n".join(out)


if __name__ == "__main__":
    login = sys.argv[1]
    data = mock() if "--mock" in sys.argv else fetch(login)
    os.makedirs("dist", exist_ok=True)
    with open("dist/telemetry.svg", "w") as f:
        f.write(render(data))
    print("wrote dist/telemetry.svg")
