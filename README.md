<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=30&duration=2800&pause=900&color=00FF9F&center=true&vCenter=true&width=900&height=55&lines=PinSQL;Backend+%7C+Networks+%7C+Systems+%7C+APIs;Break+%E2%86%92+Learn+%E2%86%92+Build+%28authorized+only%29;root%40pinsql%3A~%23+_" alt="Typing SVG" />

<a href="https://x.com/wildkenyan"><img src="./assets/terminal.svg" alt="root@pinsql terminal" width="100%" /></a>

<p>
  <a href="https://github.com/pinsql"><img src="https://img.shields.io/badge/GitHub-pinsql-00FF9F?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117" alt="GitHub @pinsql" /></a>
  &nbsp;
  <a href="https://x.com/wildkenyan"><img src="https://img.shields.io/badge/X-@wildkenyan-00FF9F?style=for-the-badge&logo=x&logoColor=white&labelColor=0d1117" alt="X @wildkenyan" /></a>
</p>

<sub><code>STATUS: ONLINE</code> · <code>STACK: PROD-GRADE</code> · <code>DISCLOSURE: ETHICAL</code> · <code>LAST_DEPLOY: WHEN_IT_COMPILES</code></sub>

<img src="./assets/hero.svg" alt="SELF-TAUGHT · BACKEND · NETWORK · SYSTEMS · OFFSEC" width="100%" />

<i>Decentralization-curious. Firewall-aware. Intrusion-informed.</i><br/>
<b>Ethically disclosed</b> findings across <b>hundreds</b> of orgs — responsible disclosure, sharp writeups, no noise.

<br/>

<a href="https://x.com/wildkenyan"><img src="./assets/neofetch.svg" alt="neofetch — root@pinsql" width="100%" /></a>

</div>

### `> ./ctf --target pinsql` 🏴

<sub>think you can pop this box? click your way in 👇</sub>

<details>
<summary><code>guest@void:~$ ssh guest@pinsql</code></summary>

```text
Connecting to pinsql:22 ...
SSH-2.0-curiosity_9.x
Warning: you are now being watched. Welcome, guest. 👁
```

<details>
<summary><code>guest@pinsql:~$ ls -la</code></summary>

```text
drwx------  root  root   4096  .
-rw-r--r--  guest guest   420  notes.txt
-r--------  root  root     37  .flag
```

<details>
<summary><code>guest@pinsql:~$ cat .flag</code></summary>

```diff
- cat: .flag: Permission denied
```

<details>
<summary><code>guest@pinsql:~$ cat notes.txt</code></summary>

```text
todo: stop leaving sudo NOPASSWD on /usr/bin/less
      ...nobody reads these anyway
```

<details>
<summary><code>guest@pinsql:~$ sudo less .flag</code></summary>

```diff
+ [*] GTFOBins: less → !/bin/sh
+ [+] uid=0(root) gid=0(root) groups=0(root)
+
+ flag{st4y_r00t_st4y_fr3sty}
```

<b>🏆 box pwned.</b> screenshot this and drop it at <a href="https://x.com/wildkenyan">@wildkenyan</a>. first blood gets a shoutout.

</details>
</details>
</details>
</details>
</details>

### `> ls -la ~/ops` 🗂

<div align="center">

<a href="https://github.com/pinsql/citadel"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=citadel&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="citadel" /></a>
<a href="https://github.com/pinsql/pinsql"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=pinsql&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="pinsql" /></a>

<a href="https://github.com/pinsql/simple-python-network-scanner"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=simple-python-network-scanner&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="simple-python-network-scanner" /></a>
<a href="https://github.com/pinsql/mac_address_scanner"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=mac_address_scanner&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="mac_address_scanner" /></a>

<a href="https://github.com/pinsql/AI-Sentiment-Analyzer"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=AI-Sentiment-Analyzer&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="AI-Sentiment-Analyzer" /></a>
<a href="https://github.com/pinsql/steveweb_protfolio"><img width="49%" src="https://github-readme-stats.vercel.app/api/pin/?username=pinsql&repo=steveweb_protfolio&show_owner=false&border_color=30363d&border_radius=10&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&description_lines_count=2" alt="steveweb_protfolio" /></a>

</div>

```text
drwxr-x---  citadel                        → hardened base of operations
drwxr-xr-x  pinsql                         → network & security d3v op.
-rwxr-xr-x  simple-python-network-scanner  → sweep the subnet, list what's alive
-rwxr-xr-x  mac_address_scanner            → who's on the wire? vendor lookup by MAC
-rw-r--r--  AI-Sentiment-Analyzer          → NLP side quest (fork)
-rw-r--r--  steveweb_protfolio             → web front, hand-rolled HTML
```

### `> cat /proc/pinsql/stats` 📈

<div align="center">

<img height="165" src="https://github-readme-stats.vercel.app/api?username=pinsql&show_icons=true&count_private=true&include_all_commits=true&hide_border=true&bg_color=0d1117&title_color=00ff9f&icon_color=00e5ff&text_color=c9d1d9&ring_color=00ff9f&custom_title=root%40pinsql%20%2F%2F%20telemetry" alt="GitHub stats" />
<img height="165" src="https://streak-stats.demolab.com?user=pinsql&hide_border=true&background=0D1117&ring=00FF9F&fire=FF2E63&currStreakLabel=00FF9F&sideLabels=C9D1D9&currStreakNum=FFFFFF&sideNums=FFFFFF&dates=6E7681&stroke=30363D" alt="streak" />

<img width="100%" src="https://github-readme-activity-graph.vercel.app/graph?username=pinsql&custom_title=%3E%20uptime%20%2F%2F%20commits%20per%20day&bg_color=0d1117&color=00ff9f&title_color=00ff9f&line=00e5ff&point=ff2e63&area=true&area_color=00ff9f&hide_border=true&radius=10" alt="activity graph" />

</div>

### `> tail -f /var/log/contributions` 🐍

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pinsql/pinsql/output/snake-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/pinsql/pinsql/output/snake-light.svg" />
  <img width="100%" alt="snake eating the contribution graph" src="https://raw.githubusercontent.com/pinsql/pinsql/output/snake-dark.svg" />
</picture>

<sub><code>[*] worm deployed · every green square consumed · no survivors</code></sub>

</div>

<div align="center">

<b>Your network. Your rules.</b><br/>
<code>sudo stay-root</code> · <code>stay Fr3sty</code> 🖤

<br/><br/>

<img src="https://komarev.com/ghpvc/?username=pinsql&color=00ff9f&style=flat-square&label=PROFILE+SCANS&labelColor=0d1117" alt="Profile views" />

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00ff9f,40:161b22,80:0d1117,100:0d1117&height=120&section=footer" width="100%" alt="footer wave" />

</div>

<!-- PinSQL profile README — pinsql/pinsql · mint/cyber theme -->
