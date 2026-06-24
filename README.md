# pcapviz

Analyseur de captures réseau **`.pcap` / `.pcapng`** portable, packagé en **un seul
binaire** (Windows / Linux), avec une interface web servie en local. Pensé pour les
environnements où Wireshark n'est pas installable.

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

Prérequis : Go ≥ 1.24, Node ≥ 20.

```sh
make build            # frontend + binaire -> bin/pcapviz
make dist             # bin/pcapviz-linux-amd64 et bin/pcapviz-windows-amd64.exe
make test             # tests Go
```

## Utilisation

```sh
./bin/pcapviz                 # ouvre http://127.0.0.1:8080 et le navigateur
./bin/pcapviz capture.pcap    # précharge une capture
./bin/pcapviz -addr 127.0.0.1:9000 -no-browser
```

Puis ouvrir un fichier via le bouton « Ouvrir un .pcap » ou en préchargeant en argument.

## Développement

Deux terminaux :

```sh
go run ./cmd/pcapviz -no-browser        # API sur :8080
cd web && npm install && npm run dev    # Vite (HMR), /api proxifié vers :8080
```

## Architecture

```
cmd/pcapviz        composition root (câblage des adapters, serveur, navigateur)
internal/domain    cœur pur : modèles, moteur de filtre, statistiques
internal/app       use cases (orchestration via les ports)
internal/port      interfaces : PacketSource, IndexStore, Decoder
internal/adapter/
  pcap             lecture/décodage gopacket -> PacketSource + Decoder
  memstore         index en mémoire -> IndexStore
  http             API REST + frontend embarqué (driving adapter)
web                application Svelte + TypeScript (Vite)
```

Règle de dépendance : `adapter → app → domain`. Le domaine n'importe aucune techno.
