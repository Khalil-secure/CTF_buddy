# CTF Buddy

[English](README.md) | Français

> Assistant CTF propulsé par l'IA, pensé aujourd'hui pour les challenges réseau, avec l'objectif d'évoluer ensuite vers un assistant CTF plus général.

CTF Buddy est actuellement centré sur les challenges réseau et les scénarios d'authentification :
- analyse de captures réseau
- inspection de protocoles
- extraction d'identifiants
- cassage de hashes d'authentification
- workflows de type DNS zone transfer

Le projet est volontairement limité pour l'instant. L'idée est d'abord de rendre le workflow réseau vraiment solide, puis d'élargir plus tard vers un assistant CTF plus général pour la crypto, le web, le reversing, ou des chaînes de résolution hybrides.

![CTF Buddy](/image.png)

Déposez un fichier `.pcapng`, décrivez le challenge, puis laissez l'agent analyser la suite.

---

## Fonctionnement

```
Vous : "challenge d'authentification réseau" + capture.pcapng
         |
         v
   [ Mind Map ] ---- classe le type de challenge à partir de la description
         |
         v
   [ Claude Opus 4.6 ] ---- boucle de raisonnement adaptative + tool use
         |
         +--> pcap_inspect()
         |    détecte les protocoles, extrait les indices, suggère la suite
         |
         +--> outils ciblés
              ntlmv2_crack · ospf_crack · dns_enum · decode · hash_crack
```

Claude lit le résultat de `pcap_inspect()` et choisit ensuite l'outil adapté, sans routage codé en dur.

---

## Types de challenges actuellement pris en charge

| Catégorie | Protocole | Technique |
|---|---|---|
| Capture réseau | FTP | Extraction USER/PASS en clair |
| Capture réseau | Telnet | Reconstruction de flux TCP |
| Capture réseau | HTTP Basic Auth | Décodage Base64 de l'en-tête Authorization |
| Capture réseau | NTLM / NTLMv2 | Extraction du hash + hashcat mode 5600 |
| Capture réseau | Kerberos | Extraction pre-auth + hashcat mode 19900 |
| Capture réseau | OSPF / MD5 | Attaque dictionnaire sur la clé d'authentification |
| DNS | Zone Transfer | AXFR sur le nameserver + extraction TXT |
| Crypto | Hash générique | hashcat avec mode configurable |
| Crypto | Caesar / ROT | Brute-force des 26 rotations |
| Crypto | Base64 / URL | Décodage multi-couches |

Testé sur des challenges réseau [Root-Me](https://www.root-me.org/).

## Périmètre actuel

Pour le moment, CTF Buddy est conçu avant tout pour les challenges orientés réseau.

Le workflow principal est donc :
- inspecter une capture
- détecter le protocole ou le mécanisme d'authentification
- extraire les éléments utiles
- casser ou décoder ces éléments
- valider le résultat comme flag, mot de passe ou secret probable

Ce n'est pas encore un framework CTF multi-catégories complet. Quelques helpers crypto existent déjà, mais le projet doit encore être compris comme un assistant réseau d'abord, pas comme un solveur universel.

## Direction future

À long terme, l'objectif est de faire évoluer CTF Buddy vers un copilote CTF plus général.

Axes envisagés :
- workflows crypto plus larges
- helpers pour les challenges web
- support de la stéganographie
- meilleur routage entre catégories de challenges
- workflows mixtes où un challenge traverse réseau, crypto et web

Pour l'instant, il faut garder cette idée simple en tête :

`CTF Buddy est d'abord un assistant pour les challenges réseau.`

---

## Installation

```bash
git clone https://github.com/<your-handle>/ctf-buddy
cd ctf-buddy

pip install -r requirements.txt
```

**Outils externes** (optionnels — seulement nécessaires pour certaines fonctionnalités basées sur tshark) :
- [Wireshark / tshark](https://www.wireshark.org/) — inspection de paquets
- [hashcat](https://hashcat.net/) — cassage accéléré de hashes

**Wordlist** — placez `rockyou.txt` dans `wordlists/` :
```bash
# Linux
cp /usr/share/wordlists/rockyou.txt wordlists/

# ou téléchargement
curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
     -o wordlists/rockyou.txt
```

**Clé API** — copiez `.env.example` vers `.env` et renseignez votre clé :
```bash
cp .env.example .env
# puis éditez .env et définissez ANTHROPIC_API_KEY=sk-ant-...
```

---

## Utilisation

```bash
# N'importe quelle capture réseau — Claude identifie le protocole
python main.py "network authentication challenge" \
  --file capture.pcapng \
  --wordlist wordlists/rockyou.txt

# NTLM
python main.py "windows authentication capture" \
  --file ntlm_auth.pcapng \
  --wordlist wordlists/rockyou.txt

# OSPF
python main.py "ospf authentication" \
  --file ospf.pcapng \
  --wordlist wordlists/rockyou.txt

# Kerberos
python main.py "kerberos capture" \
  --file kerberos.pcapng

# DNS zone transfer
python main.py "dns zone transfer challenge" \
  --domain ch11.challenge01.root-me.org \
  --server challenge01.root-me.org \
  --port 54011
```

### Terminal auxiliaire Windows

Si vous voulez utiliser CTF Buddy dans un terminal séparé pendant que vous résolvez le challenge :

```powershell
.\launch_ctf_buddy.ps1
```

Ou en double-cliquant sur :

```text
launch_ctf_buddy.cmd
```

Pour le moment, le texte du terminal reste en anglais. Cette adaptation française concerne surtout la documentation.

---

## Architecture

```
CTF_buddy/                     ← racine du dépôt
├── main.py                    point d'entrée unique
├── requirements.txt           dépendances pip
├── .env.example               modèle de clé API
│
├── CTF_buddy/                 ← package Python
│   ├── main.py                parsing des arguments CLI + mode analyse locale
│   ├── agent.py               boucle agentique Claude Opus 4.6
│   ├── mindmap.py             classification par mots-clés
│   ├── sandbox.py             couche de sécurité pour les subprocess
│   ├── validator.py           détection de flags
│   │
│   ├── tools/
│   │   ├── registry.py        schémas des outils + dispatcher
│   │   ├── network.py         outils réseau
│   │   └── crypto.py          outils crypto et décodage
│   │
│   ├── wordlists/             placez rockyou.txt ici
│   └── challenges/            placez vos fichiers de challenge ici
│
└── tests/                     suite de tests unitaires
```

### Choix de conception

**`pcap_inspect` comme point d'entrée universel** — au lieu de faire deviner le protocole à Claude, un outil fait un scan global puis retourne des résultats structurés et les prochaines étapes recommandées.

**Claude comme couche de décision** — l'agent n'est pas scripté de manière rigide. Il lit le résultat des outils, raisonne, puis choisit la suite.

**Sandbox de sécurité** — les subprocess passent par `sandbox.safe_run()` avec une allowlist de binaires et quelques garde-fous.

---

## Contribution

Les contributions sont les bienvenues, surtout pour les outils liés aux challenges qui restent dans le périmètre réseau actuel.

Consultez aussi le guide contributeur en français : [CONTRIBUTING.fr.md](CONTRIBUTING.fr.md)

### Ajouter une nouvelle capacité

1. Implémenter la logique dans `tools/network.py` ou `tools/crypto.py`
2. Enregistrer le schéma dans `tools/registry.py`
3. Mettre à jour `pcap_inspect()` si la fonctionnalité repose sur une capture réseau
4. Ajouter ou ajuster les mots-clés dans `mindmap.py`

### Idées pour la suite

- WPA/WPA2 handshake cracker
- crack de clés privées SSH
- extraction d'identifiants VoIP / SIP
- helpers pour les challenges web
- détection stéganographique

---

## Licence

MIT
