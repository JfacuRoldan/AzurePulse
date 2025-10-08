# 🟦 AzurePulse — API Logger (Go)

> **AzurePulse** est un logger d’API écrit en Go (Golang) conçu pour tracer les connexions utilisateurs.
> Il enregistre les métadonnées client et serveur dans un fichier `logs.jsonl`, masque automatiquement les champs sensibles,
> et envoie une notification synthétique vers **Discord** et **Telegram**.
> Léger, rapide et sans dépendances externes, **AzurePulse** est un outil minimaliste et fiable pour surveiller les accès à une API.

---

## ⚙️ Fonctionnalités

* `POST /login` — reçoit un JSON contenant les métadonnées client
* Ajoute côté serveur :

  * IP du client
  * Timestamp (UTC, format RFC3339)
  * UUID v4 unique
* Journalisation locale dans `logs.jsonl` (1 objet JSON/ligne)
* Envoi optionnel de notifications :

  * **Discord** (via webhook)
  * **Telegram** (via `sendMessage`)
* Masquage récursif des champs sensibles (`password`, `token`, `authorization`, etc.)
* Rate limiting par IP (par défaut : 5 requêtes / 60 secondes)
* Endpoint `GET /health` pour test de service

> Implémenté uniquement avec la **standard library Go** + un petit parseur `.env` intégré + générateur d’UUID maison.

---

## 🧱 Nom du projet : **AzurePulse**

### 💡 Signification :

* **Azure** → teinte bleue, référence à Go (souvent associé à la couleur bleue du gopher)
* **Pulse** → chaque connexion génère une “impulsion” (log + notification)
  Un nom qui évoque à la fois **vitesse, clarté et surveillance** 🌊⚡

---

## 🧩 Pile technique

* **Langage :** Go 1.21+
* **Framework HTTP :** Standard Library (`net/http`)
* **Dépendances externes :** Aucune
* **Fichier principal :** `main.go`
* **Sortie :** `logs.jsonl` (format JSON Lines)

---

## 🚀 Démarrage rapide

### 1️⃣ (Optionnel) Créer un fichier `.env`

```dotenv
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
TELEGRAM_BOT_TOKEN=123456:ABCDEF...
TELEGRAM_CHAT_ID=123456789

# Optionnel
RATE_LIMIT=5
RATE_WINDOW_SECONDS=60
```

### 2️⃣ Lancer le serveur

```bash
go run main.go
```

### 3️⃣ Tester `/login`

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "device": {
      "userAgent": "Mozilla/5.0 ...",
      "platform": "Windows",
      "language": "fr-FR",
      "screen": {"width":1920, "height":1080},
      "timezone": "Europe/Paris"
    }
  }'
```

**Réponse :**

```json
{
  "status": "ok",
  "id": "uuid-v4",
  "timestamp": "2025-10-08T15:00:00Z"
}
```

---

## 🧠 Endpoints

### `GET /health`

Renvoie :

```json
{ "status": "ok" }
```

### `POST /login`

* Lit un JSON (métadonnées client)
* Ajoute IP + timestamp + UUID
* Écrit dans `logs.jsonl`
* Envoie une notification Discord & Telegram
* Réponses possibles :

  * `200 OK` → succès
  * `400 Bad Request` → JSON invalide
  * `405 Method Not Allowed` → mauvaise méthode
  * `429 Too Many Requests` → limite atteinte
  * `500 Internal Server Error` → échec d’écriture

---

## 🗃️ Journalisation (`logs.jsonl`)

* Chaque ligne = un objet JSON complet
* Créé automatiquement à la racine du projet
* Exemple d’entrée :

```json
{
  "id": "d3e2b9b7-9b0a-4e84-9d15-2b1f1a0c0c0f",
  "timestamp": "2025-10-08T15:00:00Z",
  "ip": "192.168.1.10",
  "path": "/login",
  "method": "POST",
  "client": {
    "username": "testuser",
    "device": {
      "userAgent": "Mozilla/5.0 ...",
      "platform": "Windows",
      "language": "fr-FR",
      "screen": {"width":1920, "height":1080},
      "timezone": "Europe/Paris"
    }
  }
}
```

Lecture rapide :

```bash
tail -f logs.jsonl
```

---

## 🔔 Notifications

**Format du message envoyé :**

```
Nouvelle connexion :
- user: testuser
- ip: 192.168.1.10
- os: Windows
- lang: fr-FR
- screen: 1920x1080
- time: 2025-10-08T15:00:00Z
```

* Discord → `POST` JSON `{ "content": "..." }` à `DISCORD_WEBHOOK_URL`
* Telegram → `POST` vers `https://api.telegram.org/bot<TOKEN>/sendMessage`
* Envoi **asynchrone / best-effort** : les échecs n’interrompent pas la requête principale

---

## 🧱 Rate limiting

* Limite **par IP**
* Par défaut : `5` requêtes / `60` secondes
* Configurable via `.env` (`RATE_LIMIT`, `RATE_WINDOW_SECONDS`)
* Retourne `429 Too Many Requests` avec un en-tête `Retry-After`

---

## 🛡️ Sécurité & confidentialité

* Masquage récursif des champs sensibles :
  `password, pass, token, authorization, apikey, api_key, secret, refresh_token`
* Taille max du corps : `1 MiB`
* IP extraite via :

  * `X-Forwarded-For`
  * `X-Real-IP`
  * sinon `RemoteAddr`
* Timestamp UTC (RFC3339)
* Aucun mot de passe ni token ne quitte le serveur

---

## 🔧 Construction binaire

Compilation :

```bash
go build -o azurepulse
```

Exécution :

```bash
./azurepulse    # Linux / Mac
azurepulse.exe  # Windows
```

---

## 🧩 Structure du projet

```
├── main.go
├── logs.jsonl
└── .env
```

---

## ⚙️ Dépannage

* `go: command not found` → installez Go 1.21+
* Pas de logs → vérifier les droits d’écriture
* Pas de notification → vérifier `.env` et connectivité
* 429 → ajuster `RATE_LIMIT` ou `RATE_WINDOW_SECONDS`


---

**Auteur :** *Miro-fr* ⚙️
Lancez **AzurePulse**, et chaque connexion laissera une empreinte claire et ordonnée — rapide comme Go, précis comme un battement. 💙
