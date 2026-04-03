<div align="center">

<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 120 120">
  <defs>
    <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00d4ff"/>
      <stop offset="100%" stop-color="#7c3aed"/>
    </linearGradient>
  </defs>
  <circle cx="46" cy="46" r="30" fill="none" stroke="url(#g)" stroke-width="2.5" opacity="0.25"/>
  <circle cx="46" cy="46" r="22" fill="none" stroke="url(#g)" stroke-width="4"/>
  <line x1="63" y1="63" x2="95" y2="95" stroke="url(#g)" stroke-width="7" stroke-linecap="round"/>
</svg>

# SHERLOCK-RS

**Traque les comptes sur les réseaux sociaux à partir d'un pseudo — Édition Rust**

[![Rust](https://img.shields.io/badge/Rust-1.94+-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Licence](https://img.shields.io/badge/Licence-MIT-blue?style=flat-square)](LICENSE)
[![Sites](https://img.shields.io/badge/Sites-478+-brightgreen?style=flat-square)](https://github.com/sherlock-project/sherlock)
[![Plateforme](https://img.shields.io/badge/Plateforme-Windows-0078D4?style=flat-square&logo=windows)](https://github.com/Oli97430/sherlock-rs/releases)
[![Auteur](https://img.shields.io/badge/Auteur-Olivier%20Hoarau-purple?style=flat-square)](mailto:tarraw974@gmail.com)

*Réécriture complète en Rust de [Sherlock](https://github.com/sherlock-project/sherlock) avec une interface web sombre et moderne — un seul `.exe`, zéro installation.*

</div>

---

## Présentation

**Sherlock-RS** analyse **478+ plateformes sociales** en parallèle pour déterminer si un nom d'utilisateur existe. Il suffit de lancer l'exe : un serveur local démarre, le navigateur s'ouvre automatiquement et les résultats arrivent en temps réel.

> **Nouveau :** Recherche multi-pseudos simultanée avec onglets, rotation automatique de 25 User-Agents réels, et système de retry intelligent sur erreurs réseau.

---

## Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| 🔍 **478+ sites analysés** | Base de données Sherlock officielle, mise à jour en un clic depuis l'interface |
| 👥 **Multi-pseudos** | Saisir plusieurs noms d'un coup (virgule ou retour à la ligne), résultats par onglets |
| ⚡ **Parallélisme** | 20 requêtes simultanées via Tokio async — scan complet en quelques minutes |
| 🔄 **Rotation User-Agent** | 25 vrais navigateurs (Chrome, Firefox, Edge, Safari, Opera…) tournés aléatoirement par requête |
| 🔁 **Retry intelligent** | 3 tentatives avec backoff exponentiel (500 ms / 1 000 ms) sur erreurs réseau uniquement |
| 🎨 **Interface moderne** | UI web dark theme avec résultats en temps réel (Server-Sent Events) |
| 🛡️ **Détection WAF** | Cloudflare, PerimeterX, AWS CloudFront détectés et signalés |
| 🧅 **Proxy / Tor** | Support SOCKS5 natif (`socks5://127.0.0.1:9050` pour Tor) |
| 📥 **Export** | Téléchargement des résultats en CSV (tableur) ou TXT |
| 🔎 **Filtrage & tri** | Tri par nom, statut ou temps de réponse — filtre textuel en direct |
| 📦 **Zéro installation** | Un seul `.exe` autonome de 5 Mo, aucune dépendance requise |

---

## Installation

### Méthode rapide — Télécharger l'exécutable

1. Télécharge la dernière version depuis la page [**Releases**](https://github.com/Oli97430/sherlock-rs/releases)
2. Double-clique sur `sherlock-rs.exe`
3. Le navigateur s'ouvre automatiquement — c'est tout

### Compiler depuis les sources

**Prérequis :**
- [Rust](https://rustup.rs/) (installe via `rustup`)
- [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/fr/downloads/) avec la charge de travail *Développement Desktop en C++*

```bash
git clone https://github.com/Oli97430/sherlock-rs.git
cd sherlock-rs
cargo build --release
```

L'exécutable se trouve ensuite dans `target/release/sherlock-rs.exe`.

---

## Utilisation

```bash
sherlock-rs.exe
```

Le programme démarre un serveur local sur un port aléatoire et ouvre ton navigateur par défaut. Aucune commande supplémentaire n'est nécessaire.

### Étapes de base

1. Saisis un ou plusieurs pseudos à rechercher (séparés par une virgule ou un retour à la ligne)
2. Ajuste les options si besoin (timeout, proxy, NSFW)
3. Clique sur **Hunt** ou appuie sur `Entrée`
4. Les résultats apparaissent en temps réel, site par site
5. Exporte les résultats en CSV ou TXT via les boutons dédiés

### Recherche multi-pseudos

Le champ de saisie accepte plusieurs noms d'un coup :

```
johndoe
janedoe, alice
```

Chaque pseudo obtient son propre onglet avec un compteur de comptes trouvés mis à jour en direct. L'onglet en cours de scan pulse en bleu.

### Options de l'interface

| Option | Description |
|---|---|
| **Timeout** | Durée maximale d'attente par requête (défaut : 30 s, min : 5 s) |
| **NSFW** | Inclure les plateformes à contenu adulte dans la recherche |
| **Proxy** | URL d'un proxy SOCKS5 ou HTTP, ex. `socks5://127.0.0.1:9050` pour Tor |
| **Update DB** | Télécharge la dernière base de données des sites depuis GitHub |

### Raccourcis clavier

| Touche | Action |
|---|---|
| `Entrée` | Lancer la recherche (dans le champ pseudo) |
| `Shift + Entrée` | Passer à la ligne dans le champ (multi-pseudos) |
| `Échap` | Stopper la recherche en cours |

---

## Fonctionnement technique

### Méthodes de détection

Sherlock-RS reprend fidèlement les 3 méthodes de détection du projet original :

| Type | Logique |
|---|---|
| `status_code` | Code HTTP 404 (ou code personnalisé) → absent ; 200-299 → présent |
| `message` | Texte d'erreur spécifique trouvé dans le corps de la réponse → absent |
| `response_url` | Redirections désactivées ; code 200-299 → présent, sinon absent |

La détection WAF (Cloudflare, PerimeterX…) est appliquée **en priorité** avant toute autre logique afin d'éviter les faux positifs. Les résultats bloqués sont signalés séparément avec le statut **Bloqué**.

### Rotation des User-Agents

Chaque requête individuelle choisit aléatoirement un User-Agent parmi 25 navigateurs réels modernes :

- Chrome 128–131 (Windows, macOS, Linux, Android)
- Firefox 130–133 (Windows, macOS, Linux)
- Edge 130–131 (Windows, macOS)
- Safari 17 (macOS, iOS)
- Opera 116, Brave

Cela réduit considérablement les blocages basés sur la reconnaissance de robots.

### Retry avec backoff exponentiel

En cas d'erreur réseau (timeout, connexion refusée, DNS) :

```
Tentative 1  →  échoue  →  attente 500 ms
Tentative 2  →  échoue  →  attente 1 000 ms
Tentative 3  →  résultat final (réussite ou erreur affichée)
```

Les réponses HTTP valides (même 403 ou 404) ne déclenchent **pas** de retry.

---

## Statuts des résultats

| Statut | Signification | Conseil |
|---|---|---|
| ✅ **Trouvé** | Compte détecté sur la plateforme | Clique sur l'URL pour ouvrir le profil |
| ❌ **Non trouvé** | Aucun compte à ce nom | — |
| ⚠️ **Bloqué** | Bloqué par un WAF (Cloudflare…) | Réessaie avec un proxy ou Tor |
| 🔴 **Erreur** | Erreur réseau ou timeout après 3 tentatives | Augmente le timeout |
| ⬜ **Invalide** | Le format du pseudo ne correspond pas aux règles du site | Normal pour certains sites |

---

## Architecture du code

```
sherlock-rs/
├── Cargo.toml              # Dépendances et métadonnées du projet
├── src/
│   ├── main.rs             # Point d'entrée, bannière console, démarrage serveur
│   ├── server.rs           # Serveur Axum : routes REST + streaming SSE
│   ├── checker.rs          # Moteur de scan async : rotation UA, retry, détection
│   ├── sites.rs            # Chargement et parsing de data.json (cache local + GitHub)
│   ├── result.rs           # Types : QueryStatus (enum), QueryResult (struct)
│   └── export.rs           # Génération CSV et TXT groupés par pseudo
└── frontend/
    └── index.html          # Interface complète embarquée dans le binaire (HTML/CSS/JS)
```

### Bibliothèques utilisées (crates Rust)

| Rôle | Crate |
|---|---|
| Runtime asynchrone | `tokio 1` |
| Serveur web + SSE | `axum 0.7` |
| Client HTTP | `reqwest 0.12` |
| Sérialisation JSON | `serde` + `serde_json` |
| Expressions régulières | `regex` |
| Aléatoire (rotation UA) | `rand 0.8` |
| Export CSV | `csv` |
| Ouverture du navigateur | `open` |
| Répertoires système | `dirs` |
| Gestion d'erreurs | `anyhow` |

---

## Crédits

- **Auteur** : Olivier Hoarau — [tarraw974@gmail.com](mailto:tarraw974@gmail.com)
- **Projet original** : [Sherlock Project](https://github.com/sherlock-project/sherlock) par [@sdushantha](https://github.com/sdushantha) et la communauté (licence MIT)
- **Base de données** : `data.json` maintenu par la communauté Sherlock Project

---

## Licence

MIT — voir le fichier [LICENSE](LICENSE)

---

<div align="center">
  <sub>Développé avec passion et Rust 🦀 — Olivier Hoarau</sub>
</div>
