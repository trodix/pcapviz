# pcapviz

Analyseur de captures réseau **`.pcap` / `.pcapng`** portable (Windows / Linux), pensé
pour les environnements où Wireshark n'est pas installable. Deux interfaces partageant
le même cœur Go :

- **Serveur web** (`pcapviz`) — ouvre l'UI dans le navigateur. Binaire **unique, pur Go,
  statique**, cross-compilé trivialement.
- **Application desktop** (`pcapviz-desktop`) — fenêtre **webview native de l'OS**
  (WebKitGTK sous Linux, WebView2 sous Windows). Pas de Chromium embarqué : **bien moins
  de RAM qu'Electron**.

Sous le capot :

- **Backend Go** — lecture pcap/pcapng 100 % pure Go (gopacket/pcapgo, sans libpcap),
  perf quasi-native, frontend embarqué dans le binaire (`//go:embed`).
- **Frontend Svelte + TypeScript** — liste de paquets virtualisée, vue détail en arbre,
  dashboard de statistiques.
- **Architecture hexagonale légère** (`domain` / `app` / `port` / `adapter`).

## Fonctions (v1)

- **Inspection type Wireshark** : liste paginée + détail des couches + hex dump.
- **Filtre d'affichage** : `tcp.port == 443 && ip.addr == 10.0.0.1`, `dns`, `!arp`,
  `length > 100`, `tls.sni == example.com`…
- **Statistiques** : répartition par protocole, top talkers, conversations, timeline.
- **Extraction applicative** : noms DNS, `Host`/méthode/URI HTTP, SNI TLS.

## Build

Prérequis communs : Go ≥ 1.24, Node ≥ 20.

### Serveur web (pur Go, portable)

```sh
make build            # frontend + binaire -> bin/pcapviz
make dist             # bin/pcapviz-linux-amd64 et bin/pcapviz-windows-amd64.exe
make test             # tests Go
```

### Application desktop (webview native)

```sh
make desktop          # bin/pcapviz-desktop          (Linux natif)
make desktop-windows  # bin/pcapviz-desktop-windows-amd64.exe (cross-compilé depuis Linux)
make desktop-all      # les deux
```

- **Linux** : build natif, nécessite `gcc`, `gtk3` et `webkit2gtk-4.1` (paquets
  `gtk3-devel` + `webkit2gtk4.1-devel` sur Fedora). Au runtime : WebKitGTK installé.
- **Windows** : cross-compilé depuis Linux (go-webview2, pur Go, sans CGO). Au runtime :
  le runtime WebView2 — déjà présent sur Windows 10/11.
- Wails n'est volontairement pas utilisé : il ne supporte pas la cross-compilation, ce qui
  empêcherait de produire le `.exe` Windows depuis Linux.

## Utilisation

### Serveur web

```sh
./bin/pcapviz                 # ouvre http://127.0.0.1:8080 et le navigateur
./bin/pcapviz capture.pcap    # précharge une capture
./bin/pcapviz -addr 127.0.0.1:9000 -no-browser
```

### Desktop

```sh
./bin/pcapviz-desktop                 # fenêtre native standalone
./bin/pcapviz-desktop capture.pcap    # précharge une capture
```

Puis ouvrir un fichier via le bouton « Ouvrir un .pcap » ou en préchargeant en argument.

## Debug & logs

Pas de fichier de log créé au démarrage. À la place :

- **Logs en mémoire** (ring buffer ~2000 entrées) + sortie stderr, consultables **dans
  l'app** via l'onglet **Logs** : filtre par niveau (error/warn/info/debug), **toggle
  Debug à chaud** (les logs debug ne sont pas stockés tant qu'il est off), auto-refresh,
  et bouton **Télécharger** (pour joindre à un rapport de bug).
- **Récupération des panics HTTP** : une requête qui plante n'abat pas le serveur, la
  stack est loguée en `error`.
- **Rapport de crash** écrit **uniquement en cas de crash** dans
  `~/.cache/pcapviz/crashes/` (panic + stack + logs récents). Consultable dans l'onglet
  Logs après redémarrage (utile car le buffer mémoire est perdu au crash).

Démarrer avec le debug activé : `./bin/pcapviz -debug` (ou `pcapviz-desktop -debug`).
API : `GET /api/logs`, `GET|POST /api/logs/level`, `GET /api/crashes`.

## CI / Releases (GitHub Actions)

- **CI** (`.github/workflows/ci.yml`) — sur push/PR (`main`, `develop`) : build du
  frontend, `go vet`, `go test`, puis build des 4 binaires (le runner installe
  `libgtk-3-dev` + `libwebkit2gtk-4.1-dev` pour le desktop Linux).
- **Release** (`.github/workflows/release.yml`) — sur tag `v*` : build des 4 binaires
  et publication d'une **GitHub Release** avec les artefacts attachés.

```sh
git tag v1.0.0 && git push origin v1.0.0   # déclenche la release
```

Binaires publiés : `pcapviz-linux-amd64`, `pcapviz-windows-amd64.exe`,
`pcapviz-desktop-linux-amd64`, `pcapviz-desktop-windows-amd64.exe`. La logique de build
est partagée dans `.github/build.sh`.

## Développement

Deux terminaux :

```sh
go run ./cmd/pcapviz -no-browser        # API sur :8080
cd web && npm install && npm run dev    # Vite (HMR), /api proxifié vers :8080
```

## Architecture

```
cmd/pcapviz          entrypoint serveur web (ouvre le navigateur)
cmd/pcapviz-desktop  entrypoint desktop (fenêtre webview native)
internal/bootstrap   câblage partagé des adapters (composition root)
internal/domain      cœur pur : modèles, moteur de filtre, statistiques
internal/app         use cases (orchestration via les ports)
internal/port        interfaces : PacketSource, IndexStore, Decoder
internal/adapter/
  pcap               lecture/décodage gopacket -> PacketSource + Decoder
  memstore           index en mémoire -> IndexStore
  http               API REST + frontend embarqué (driving adapter)
internal/desktop     webview native par OS (cgo WebKitGTK / go-webview2), build tags
web                  application Svelte + TypeScript (Vite)
```

Règle de dépendance : `adapter → app → domain`. Le domaine n'importe aucune techno.
