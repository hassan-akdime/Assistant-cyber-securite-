# Assistant cybersécurité

Assistant qui reçoit une demande en **texte**, en **image** (capture d'écran d'un email, de logs, d'une alerte) ou les deux, la classe avec un LLM, puis répond. Les **incidents** sont analysés, enregistrés dans MongoDB et envoyés par email à l'équipe de sécurité, qui peut les marquer comme traités en un clic.

## Fonctionnement

Le workflow est un graphe [LangGraph](https://langchain-ai.github.io/langgraph/) :

1. **Lecture de l'image** (si jointe) par un modèle de vision, qui la transcrit en texte.
2. **Routeur LLM** : classe la demande dans l'une des trois routes.
3. **Route choisie** :

| Route | Cas d'usage | Résultat |
|---|---|---|
| `CYBER_INFO` | Question générale de cybersécurité | Réponse pédagogique |
| `CYBER_INCIDENT` | Cas concret (phishing, ransomware, logs suspects, alerte) | Analyse en 6 sections, enregistrement en base, email à l'équipe |
| `GENERAL` | Tout le reste | Réponse de l'assistant généraliste |

L'analyse d'incident contient : résumé, type probable, gravité, indicateurs de compromission, actions de confinement, remédiation.

## Cycle de vie d'un incident

1. Le rapport est envoyé à `TEAM_EMAIL` avec le statut « En cours de traitement » et un bouton **Traitement**.
2. L'incident est enregistré dans MongoDB avec `statut: "non traité"`.
3. Le clic ouvre une page de confirmation (le simple clic ne modifie rien, pour résister aux scanners de liens des passerelles mail).
4. Après « Confirmer le traitement », le statut passe à `"traité"`.

L'email n'affiche que la section pertinente : le texte saisi, le contenu extrait de l'image, ou les deux si les deux existent. L'image d'origine est jointe.

## Prérequis

- Python 3.10 ou plus
- Un serveur MongoDB (local ou [Atlas](https://www.mongodb.com/atlas))
- Une clé API [OpenRouter](https://openrouter.ai/settings/keys)
- Un compte email expéditeur (SMTP). Pour Gmail : validation en deux étapes activée et [mot de passe d'application](https://myaccount.google.com/apppasswords)

## Installation

```bash
python -m pip install -U gradio langchain-openrouter langgraph pymongo uvicorn fastapi
```

## Configuration

Tous les paramètres sont des constantes en haut de `cyber_router_gui.py` :

| Constante | Rôle |
|---|---|
| `OPENROUTER_API_KEY` | Clé OpenRouter |
| `TEXT_MODEL`, `VISION_MODEL` | Modèles texte et vision (le second doit accepter les images) |
| `TEAM_EMAIL` | Adresse fixe de l'équipe qui reçoit les incidents |
| `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | Compte expéditeur (587 : STARTTLS, 465 : SSL) |
| `MONGO_URI`, `MONGO_DB`, `MONGO_INCIDENTS_COLLECTION` | Base et collection des incidents |
| `HOST`, `PORT`, `BASE_URL` | Serveur local et adresse écrite dans le lien de l'email |

`BASE_URL` doit être joignable depuis les postes de l'équipe (par exemple `http://192.168.1.20:8000`). Pour accepter les connexions du réseau, mettre `HOST = "0.0.0.0"`.

## Lancement

```bash
python cyber_router_gui.py
```

Ouvrir `http://127.0.0.1:8000`. Exemples à essayer :

- **Incident** : « Un collaborateur a cliqué sur un lien dans un email se faisant passer pour les RH et a saisi son mot de passe. »
- **Information** : « Quelle est la différence entre un IDS et un IPS ? »
- **Hors domaine** : « Explique-moi la photosynthèse. »

## Données stockées dans MongoDB

Collection `incidents` :

| Champ | Contenu |
|---|---|
| `_id` | Jeton aléatoire (identifiant et clé du lien de l'email) |
| `statut` | `non traité`, puis `traité` |
| `date_signalement`, `date_traitement` | Dates d'envoi et de confirmation |
| `message`, `extraction_image` | Texte saisi et/ou texte lu dans l'image |
| `type` | `texte`, `image` ou `texte+image` |

Pour lister les incidents ouverts : `db.incidents.find({ statut: "non traité" })`

## Dépannage

| Symptôme | Piste |
|---|---|
| `ModuleNotFoundError: langchain_openrouter` | `python -m pip install -U langchain-openrouter` dans le même Python que le script |
| Réponse vide | Modèle à raisonnement qui épuise `max_tokens` : choisir un modèle précis ou augmenter la limite |
| `Connection unexpectedly closed` (email) | Essayer `SMTP_PORT = 465`, vérifier pare-feu, VPN et antivirus |
| Pas de bouton « Traitement » dans l'email | MongoDB injoignable au moment de l'envoi : vérifier `MONGO_URI` |

## Sécurité

- La clé OpenRouter et le mot de passe SMTP sont écrits dans le fichier : ne pas le versionner ni le partager (ajouter à `.gitignore`).
- Si `HOST = "0.0.0.0"`, l'interface (et donc l'usage de la clé OpenRouter) devient accessible depuis le réseau : l'isoler (VPN, pare-feu) ou ajouter une authentification.
- Les textes et images d'incident sont envoyés au fournisseur du modèle via OpenRouter : les anonymiser si besoin.
- L'analyse est générée automatiquement : l'équipe doit la vérifier avant toute action.

