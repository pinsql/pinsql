<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=30&duration=2800&pause=900&color=00FF9F&center=true&vCenter=true&width=900&height=55&lines=hey%2C+it%27s+pinsql+%F0%9F%91%8B;i+break+stuff+%28with+permission%29;then+i+fix+it+%28sometimes%29;your+firewall+looks+nervous+rn;root%40pinsql%3A~%23+_" alt="Typing SVG" />

<a href="https://x.com/wildkenyan"><img src="./assets/terminal.svg" alt="root@pinsql terminal" width="100%" /></a>

<p>
  <a href="https://github.com/pinsql"><img src="https://img.shields.io/badge/GitHub-pinsql-00FF9F?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117" alt="GitHub @pinsql" /></a>
  &nbsp;
  <a href="https://x.com/wildkenyan"><img src="https://img.shields.io/badge/X-@wildkenyan-00FF9F?style=for-the-badge&logo=x&logoColor=white&labelColor=0d1117" alt="X @wildkenyan" /></a>
</p>

<sub><code>MOOD: smug</code> · <code>SLEEP: deprecated</code> · <code>BUGS: found, not made (mostly)</code> · <code>DEPLOYS: fridays 😈</code></sub>

<img src="./assets/hero.svg" alt="SELF-TAUGHT · BACKEND · NETWORK · SYSTEMS · OFFSEC" width="100%" />

<i>i poke your app till it spills its secrets, then hand them back with a bow on top.</i><br/>
bugs reported to <b>hundreds</b> of orgs. no ransom, no drama, just one very smug email. 💅

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

<a href="https://github.com/pinsql?tab=repositories"><img src="./assets/ops.svg" alt="ls -la ~/ops — pinsql projects" width="100%" /></a>

<sub><a href="https://github.com/pinsql/citadel"><code>citadel</code></a> · <a href="https://github.com/pinsql/simple-python-network-scanner"><code>network-scanner</code></a> · <a href="https://github.com/pinsql/mac_address_scanner"><code>mac_scanner</code></a> · <a href="https://github.com/pinsql/AI-Sentiment-Analyzer"><code>sentiment</code></a></sub>

</div>

### `> ./telemetry --window 365d` 📡

<div align="center">

<img src="https://raw.githubusercontent.com/pinsql/pinsql/output/telemetry.svg" alt="pinsql telemetry" width="100%" />

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

<b>rules suck.</b> i read them anyway, then find the loophole.<br/>
<code>sudo stay-root</code> · <code>stay Fr3sty</code> 🖤

<br/><br/>

<img src="https://komarev.com/ghpvc/?username=pinsql&color=00ff9f&style=flat-square&label=PROFILE+SCANS&labelColor=0d1117" alt="Profile views" />

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00ff9f,40:161b22,80:0d1117,100:0d1117&height=120&section=footer" width="100%" alt="footer wave" />

</div>

<!-- PinSQL profile README — pinsql/pinsql · mint/cyber theme -->
