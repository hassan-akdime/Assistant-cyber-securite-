import base64
import html
import mimetypes
import secrets
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import Literal
from typing_extensions import TypedDict

import gradio as gr
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from langchain_core.messages import HumanMessage
from langchain_openrouter import ChatOpenRouter
from langgraph.graph import StateGraph, START, END
from pymongo import MongoClient


# 1. Configuration des LLM
# >>> Renseignez votre clé OpenRouter ici <<<
OPENROUTER_API_KEY = "sk-or..."

TEXT_MODEL = "openrouter/auto"
# VISION_MODEL doit être un modèle capable de lire des images.
VISION_MODEL = "google/gemini-2.5-flash"

text_model = ChatOpenRouter(
    model=TEXT_MODEL,
    api_key=OPENROUTER_API_KEY,
    temperature=0,
    max_tokens=1500,
)

vision_model = ChatOpenRouter(
    model=VISION_MODEL,
    api_key=OPENROUTER_API_KEY,
    temperature=0,
    max_tokens=1000,
)


# 1b. Configuration de l'envoi d'email à l'équipe
# Adresse de l'équipe qui reçoit les analyses d'incidents (fixe).
TEAM_EMAIL = "....@gmail.com"

# Compte expéditeur (serveur SMTP). Exemple Gmail : smtp.gmail.com / 587
# avec un "mot de passe d'application" (pas le mot de passe du compte).
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "....@gmail.com"
SMTP_PASSWORD = "....."


# 1c. Configuration MongoDB et serveur web (bouton "Traitement")
MONGO_URI = "mongodb+srv..."
MONGO_DB = "CyberDB"
# Collection unique : chaque incident y est enregistré avec le statut
# "non traité", puis passe à "traité" au clic sur le bouton de l'email.
MONGO_INCIDENTS_COLLECTION = "Incident"

# Serveur local. BASE_URL est l'adresse utilisée dans le lien de l'email :
# elle doit être joignable depuis les postes de l'équipe
# (ex. "http://192.168.1.20:8000" ou l'adresse publique du serveur).
HOST = "127.0.0.1"
PORT = 8000
BASE_URL = "http://localhost:8000"


# 2. État partagé
class State(TypedDict):
    request: str            # texte saisi par l'utilisateur (peut être vide)
    image_path: str         # chemin de l'image importée (peut être vide)
    image_description: str  # transcription/description de l'image
    category: str
    answer: str
    email_status: str       # résultat de l'envoi à l'équipe


# 3. Utilitaires
def get_text(response) -> str:
    """Extrait le texte d'une réponse, même si le contenu est une liste de blocs."""
    content = response.content
    if isinstance(content, list):
        content = "".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )
    return (content or "").strip()


def full_request(state: State) -> str:
    """Combine le texte saisi et le contenu extrait de l'image."""
    parts = []
    if state["request"]:
        parts.append(state["request"])
    if state["image_description"]:
        parts.append(
            "[Contenu de l'image jointe]\n" + state["image_description"]
        )
    return "\n\n".join(parts)


def ask(system_prompt: str, state: State) -> str:
    response = text_model.invoke([
        ("system", system_prompt),
        ("human", full_request(state)),
    ])
    text = get_text(response)
    return text or (
        "Le modèle n'a renvoyé aucune réponse. "
        "Réessayez ou changez de modèle (variable TEXT_MODEL)."
    )


# 4. Nœud image : transcription de l'image en texte
def describe_image(state: State):
    path = state["image_path"]
    if not path:
        return {"image_description": ""}

    print("\nImage : analyse de l'image importée...")

    mime = mimetypes.guess_type(path)[0] or "image/png"
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()

    message = HumanMessage(content=[
        {
            "type": "text",
            "text": (
                "Tu assistes un analyste en cybersécurité. "
                "Transcris fidèlement tout le texte visible dans cette "
                "image (logs, emails, en-têtes, messages d'erreur, "
                "adresses IP, URL, noms de fichiers, alertes), puis "
                "décris brièvement ce qui est visible. "
                "N'interprète pas et n'invente rien."
            ),
        },
        {
            "type": "image_url",
            "image_url": {"url": f"data:{mime};base64,{b64}"},
        },
    ])

    response = vision_model.invoke([message])
    return {"image_description": get_text(response)}


# 5. Nœud routeur : classification de la demande
def router(state: State):
    print("\nRouter : analyse de la demande...")

    response = text_model.invoke([
        (
            "system",
            "Tu es un routeur de requêtes. Classe la demande de "
            "l'utilisateur (texte et/ou contenu d'image) dans exactement "
            "UNE catégorie :\n"
            "CYBER_INFO : questions générales ou informations sur la "
            "cybersécurité (concepts, bonnes pratiques, menaces, "
            "normes, outils, prévention).\n"
            "CYBER_INCIDENT : description, analyse ou gestion d'un "
            "incident de cybersécurité concret (logs suspects, "
            "phishing reçu, ransomware, intrusion, compromission, "
            "alerte SIEM, comportement anormal, capture d'écran "
            "d'un email ou d'une alerte suspecte).\n"
            "GENERAL : toutes les autres demandes, hors cybersécurité.\n\n"
            "Réponds UNIQUEMENT avec le nom de la catégorie. "
            "Aucune explication, aucune ponctuation."
        ),
        ("human", full_request(state)),
    ])

    category = get_text(response).upper()

    allowed_categories = {"CYBER_INFO", "CYBER_INCIDENT", "GENERAL"}
    if category not in allowed_categories:
        category = "GENERAL"

    print(f"Router : catégorie sélectionnée = {category}")
    return {"category": category}


# 6. Route 1 : questions et infos cybersécurité
def cyber_info(state: State):
    print("Nœud : Cyber Info")
    return {"answer": ask(
        "Tu es un expert en cybersécurité et un pédagogue. "
        "Réponds de façon claire, précise et structurée aux "
        "questions de cybersécurité. Donne des exemples concrets "
        "et des bonnes pratiques. Réponds dans la langue de "
        "l'utilisateur.",
        state,
    )}


# 7. Route 2 : analyse des incidents cybersécurité
def cyber_incident(state: State):
    print("Nœud : Analyse d'incident")
    return {"answer": ask(
        "Tu es un analyste SOC / réponse à incident. "
        "À partir de la description fournie (texte et/ou contenu "
        "extrait d'une image), produis une analyse structurée avec "
        "les sections suivantes :\n"
        "1. Résumé de l'incident\n"
        "2. Type d'incident probable\n"
        "3. Niveau de gravité (FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE) "
        "avec justification\n"
        "4. Indicateurs de compromission à vérifier\n"
        "5. Actions immédiates de confinement\n"
        "6. Actions de remédiation et de prévention\n"
        "Si des informations manquent, indique-les clairement "
        "au lieu d'inventer. Réponds dans la langue de "
        "l'utilisateur.",
        state,
    )}


# 8. Route 3 : questions générales hors domaine
def general_answer(state: State):
    print("Nœud : Assistant général")
    return {"answer": ask(
        "Tu es un assistant généraliste serviable. "
        "Réponds clairement dans la langue de l'utilisateur. "
        "Précise brièvement que ton domaine de spécialité est la "
        "cybersécurité si la question est très éloignée.",
        state,
    )}


# 8a. MongoDB : stockage des incidents
mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
mongo_db = mongo_client[MONGO_DB]
incidents_collection = mongo_db[MONGO_INCIDENTS_COLLECTION]


def build_incident_document(state: State, token: str) -> dict:
    """Document à stocker : message reçu (texte) et/ou extraction de l'image."""
    doc = {
        "_id": token,
        "statut": "non traité",
        "date_signalement": datetime.now(),
    }

    if state["request"]:
        doc["message"] = state["request"]
    if state["image_description"]:
        doc["extraction_image"] = state["image_description"]

    if state["request"] and state["image_description"]:
        doc["type"] = "texte+image"
    elif state["image_description"]:
        doc["type"] = "image"
    else:
        doc["type"] = "texte"

    return doc


# 8b. Envoi de l'analyse d'incident à l'équipe par email
def notify_team(state: State):
    print("Nœud : Envoi à l'équipe")

    # Ne pas envoyer d'email si le modèle n'a produit aucune analyse
    if state["answer"].startswith("Le modèle n'a renvoyé aucune réponse"):
        status = "Aucun email envoyé : le modèle n'a produit aucune analyse."
        print(status)
        return {"email_status": status}

    # Enregistrer l'incident avec le statut "non traité" : le clic sur
    # le bouton de l'email le fera passer à "traité".
    token = secrets.token_urlsafe(16)
    treat_url = None
    db_warning = ""
    try:
        incidents_collection.insert_one(build_incident_document(state, token))
        treat_url = f"{BASE_URL}/traitement/{token}"
    except Exception as e:
        db_warning = (
            " Bouton 'Traitement' indisponible "
            f"(MongoDB : {type(e).__name__})."
        )

    msg = EmailMessage()
    msg["Subject"] = (
        "[ALERTE CYBERSÉCURITÉ] Nouvel incident - "
        f"{datetime.now():%Y-%m-%d %H:%M}"
    )
    msg["From"] = SMTP_USER
    msg["To"] = TEAM_EMAIL

    date_str = f"{datetime.now():%Y-%m-%d %H:%M:%S}"

    # Sections du rapport : seulement celles qui s'appliquent
    sections = []
    if state["request"]:
        sections.append(
            ("DEMANDE / DESCRIPTION DE L'INCIDENT", state["request"])
        )
    if state["image_description"]:
        sections.append(
            ("CONTENU EXTRAIT DE L'IMAGE JOINTE", state["image_description"])
        )
    if not sections:
        sections.append(
            ("DESCRIPTION", "(Aucune description disponible pour cet incident.)")
        )
    sections.append(("ANALYSE AUTOMATIQUE (LLM)", state["answer"]))

    disclaimer = (
        "Cette analyse est générée automatiquement et doit être "
        "vérifiée par l'équipe avant toute action."
    )

    # --- Version texte (clients mail sans HTML) ---
    body = (
        "Un nouvel incident de cybersécurité a été signalé.\n"
        f"Date : {date_str}\n\n"
    )
    for title, content in sections:
        body += f"=== {title} ===\n{content}\n\n"
    body += disclaimer + "\n\n"
    body += "Statut : EN COURS DE TRAITEMENT\n"
    if treat_url:
        body += f"Traitement : {treat_url}\n"
    msg.set_content(body)

    # --- Version HTML (statut + bouton "Traitement" en bas du rapport) ---
    esc = html.escape
    html_body = (
        '<html><body style="font-family:Arial,sans-serif;color:#222;">'
        "<p>Un nouvel incident de cybersécurité a été signalé.<br>"
        f"Date : {esc(date_str)}</p>"
    )
    for title, content in sections:
        html_body += (
            f'<h3 style="margin-bottom:4px;">{esc(title)}</h3>'
            '<div style="white-space:pre-wrap;border-left:3px solid #ccc;'
            f'padding-left:10px;">{esc(content)}</div>'
        )
    html_body += (
        f'<p style="color:#666;font-size:12px;"><em>{esc(disclaimer)}</em></p>'
        "<hr>"
        "<p><strong>Statut :</strong> "
        '<span style="background:#fff3cd;color:#8a6d00;padding:3px 8px;'
        'border-radius:4px;">En cours de traitement</span></p>'
    )
    if treat_url:
        html_body += (
            f'<p><a href="{esc(treat_url)}" '
            'style="display:inline-block;background:#1a73e8;color:#ffffff;'
            "padding:10px 22px;border-radius:5px;text-decoration:none;"
            'font-weight:bold;">Traitement</a></p>'
        )
    else:
        html_body += (
            "<p><em>Bouton « Traitement » indisponible "
            "(base de données injoignable).</em></p>"
        )
    html_body += "</body></html>"
    msg.add_alternative(html_body, subtype="html")

    # Joindre l'image d'origine si elle existe
    if state["image_path"]:
        mime = mimetypes.guess_type(state["image_path"])[0] or "image/png"
        maintype, subtype = mime.split("/", 1)
        with open(state["image_path"], "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype=maintype,
                subtype=subtype,
                filename=state["image_path"].replace("\\", "/").split("/")[-1],
            )

    try:
        if SMTP_PORT == 465:
            # SSL direct
            server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=30)
        else:
            # STARTTLS (port 587)
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()

        # server.set_debuglevel(1)  # décommenter pour voir le dialogue SMTP
        with server:
            server.login(SMTP_USER, SMTP_PASSWORD.replace(" ", ""))
            server.send_message(msg)
        status = f"Analyse envoyée à {TEAM_EMAIL}." + db_warning
    except smtplib.SMTPAuthenticationError:
        status = (
            "Échec d'authentification : vérifiez SMTP_USER et le mot de "
            "passe d'application (16 caractères)."
        )
    except Exception as e:
        status = (
            f"Échec de l'envoi à {TEAM_EMAIL} : "
            f"{type(e).__name__}: {e}"
        )

    print(status)
    return {"email_status": status}


# 9. Fonction de routage
def choose_route(
    state: State,
) -> Literal["cyber_info", "cyber_incident", "general_answer"]:
    routes = {
        "CYBER_INFO": "cyber_info",
        "CYBER_INCIDENT": "cyber_incident",
        "GENERAL": "general_answer",
    }
    return routes.get(state["category"], "general_answer")


# 10. Construction du graphe
workflow = StateGraph(State)

workflow.add_node("describe_image", describe_image)
workflow.add_node("router", router)
workflow.add_node("cyber_info", cyber_info)
workflow.add_node("cyber_incident", cyber_incident)
workflow.add_node("general_answer", general_answer)
workflow.add_node("notify_team", notify_team)

workflow.add_edge(START, "describe_image")
workflow.add_edge("describe_image", "router")

workflow.add_conditional_edges(
    "router",
    choose_route,
    {
        "cyber_info": "cyber_info",
        "cyber_incident": "cyber_incident",
        "general_answer": "general_answer",
    },
)

workflow.add_edge("cyber_info", END)
workflow.add_edge("cyber_incident", "notify_team")
workflow.add_edge("notify_team", END)
workflow.add_edge("general_answer", END)

app = workflow.compile()


# 11. Interface graphique (Gradio)
# Les styles sont injectés via un composant HTML : cela fonctionne quelle
# que soit la version de Gradio (5.x ou 6.x) et avec mount_gradio_app.
CSS = """
@import url("https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700&family=JetBrains+Mono:wght@400&family=Public+Sans:wght@400;500;600&display=swap");

body, gradio-app { background: #E9EDF2 !important; }

.gradio-container {
  color-scheme: light;
  --font: "Public Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Consolas, monospace;
  --body-background-fill: #E9EDF2;
  --background-fill-primary: #FBFCFD;
  --background-fill-secondary: #F2F5F8;
  --block-background-fill: #FBFCFD;
  --body-text-color: #16213A;
  --body-text-color-subdued: #55627A;
  --block-title-text-color: #16213A;
  --block-label-text-color: #55627A;
  --border-color-primary: #C9D1DC;
  --block-border-color: #C9D1DC;
  --input-background-fill: #FFFFFF;
  --input-border-color: #C9D1DC;
  --input-border-color-focus: #16213A;
  --input-shadow: none;
  --input-shadow-focus: 0 0 0 2px rgba(22, 33, 58, 0.15);
  --block-shadow: none;
  --block-radius: 6px;
  --input-radius: 6px;
  --button-large-radius: 6px;
  --button-primary-background-fill: #16213A;
  --button-primary-background-fill-hover: #263859;
  --button-primary-text-color: #FFFFFF;
  --button-primary-border-color: #16213A;
  --button-secondary-background-fill: transparent;
  --button-secondary-background-fill-hover: #DDE3EB;
  --button-secondary-text-color: #16213A;
  --button-secondary-border-color: #C9D1DC;
  background: #E9EDF2;
  max-width: 1180px !important;
  margin: 0 auto;
}

.gradio-container :focus-visible {
  outline: 2px solid #2F5D8C;
  outline-offset: 2px;
}

footer { display: none !important; }

.desk-header { padding: 8px 0 20px; }
.desk-header h1 {
  font-family: "Bricolage Grotesque", var(--font);
  font-weight: 700;
  font-size: 2.1rem;
  line-height: 1.1;
  letter-spacing: -0.02em;
  margin: 0 0 8px;
  color: #16213A;
}
.desk-header p {
  max-width: 60ch;
  margin: 0;
  color: #55627A;
  font-size: 1rem;
  line-height: 1.5;
}

/* Bandeau de tri : l'élément central de l'interface */
.band {
  border: 1px solid #C9D1DC;
  border-left-width: 8px;
  border-radius: 4px;
  background: #FBFCFD;
  padding: 14px 18px;
}
.band-title {
  font-family: "Bricolage Grotesque", var(--font);
  font-weight: 700;
  font-size: 1.4rem;
  line-height: 1.2;
  margin-bottom: 4px;
  color: #16213A;
}
.band-detail { color: #55627A; font-size: 0.95rem; line-height: 1.45; }
.band-info { border-left-color: #2F5D8C; }
.band-general { border-left-color: #7A8599; }
.band-neutral { border-left-color: #C9D1DC; }
.band-neutral .band-title { color: #55627A; }
.band-warn { border-left-color: #A8741A; }
.band-incident { border-left-color: #C8362B; background: #FDF3F1; }
.band-incident .band-title { color: #8F2118; }
.band-error { border-left-color: #C8362B; background: #FDF3F1; }
.band-error .band-title { color: #8F2118; }

.notice {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  align-items: baseline;
  margin-top: 10px;
  padding: 10px 14px;
  border-radius: 4px;
  font-size: 0.92rem;
  line-height: 1.45;
}
.notice strong { font-weight: 600; }
.notice-ok { background: #E6F2EC; color: #1B5E45; }
.notice-fail { background: #FDF3F1; color: #8F2118; }

.answer {
  background: #FBFCFD;
  border: 1px solid #C9D1DC;
  border-radius: 6px;
  padding: 18px 22px;
  margin-top: 10px;
  line-height: 1.6;
}
.answer p, .answer li { max-width: 72ch; }

.transcription textarea {
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.5;
}

@media (max-width: 640px) {
  .desk-header h1 { font-size: 1.7rem; }
  .band { padding: 12px 14px; }
  .answer { padding: 14px 16px; }
}
"""

HEADER_HTML = (
    "<style>" + CSS + "</style>"
    '<header class="desk-header">'
    "<h1>Assistant cybersécurité</h1>"
    "<p>Posez une question, décrivez un incident ou importez une capture "
    "d'écran. Les incidents sont analysés puis transmis à l'équipe.</p>"
    "</header>"
)


def band_html(kind: str, title: str, detail: str) -> str:
    return (
        f'<div class="band band-{kind}">'
        f'<div class="band-title">{html.escape(title)}</div>'
        f'<div class="band-detail">{html.escape(detail)}</div>'
        "</div>"
    )


def notice_html(category: str, status: str) -> str:
    """Statut de la notification : affiché seulement pour les incidents."""
    if category != "CYBER_INCIDENT":
        return ""
    ok = status.startswith("Analyse envoyée")
    kind = "ok" if ok else "fail"
    title = "Équipe notifiée" if ok else "Notification non envoyée"
    return (
        f'<div class="notice notice-{kind}">'
        f"<strong>{title}</strong>"
        f"<span>{html.escape(status)}</span>"
        "</div>"
    )


EMPTY_BAND = band_html(
    "neutral",
    "En attente d'une demande",
    "Le résultat de l'analyse apparaîtra ici.",
)

ROUTE_BANDS = {
    "CYBER_INFO": (
        "info",
        "Question de cybersécurité",
        "Réponse pédagogique. Aucun incident n'est créé.",
    ),
    "CYBER_INCIDENT": (
        "incident",
        "Incident de cybersécurité",
        "Analyse produite pour l'équipe.",
    ),
    "GENERAL": (
        "general",
        "Hors cybersécurité",
        "Réponse générale. Aucun incident n'est créé.",
    ),
}


def run(text, image_path):
    text = (text or "").strip()

    if not text and not image_path:
        return (
            band_html(
                "warn",
                "Rien à analyser",
                "Ajoutez un texte ou une image, puis relancez l'analyse.",
            ),
            "",
            gr.update(value="", visible=False),
            "",
        )

    try:
        result = app.invoke({
            "request": text,
            "image_path": image_path or "",
            "image_description": "",
            "category": "",
            "answer": "",
            "email_status": "",
        })
    except Exception as e:
        return (
            band_html(
                "error",
                "L'analyse a échoué",
                f"{type(e).__name__}: {e}. Vérifiez la clé OpenRouter et "
                "la connexion, puis relancez l'analyse.",
            ),
            "",
            gr.update(value="", visible=False),
            "",
        )

    kind, title, detail = ROUTE_BANDS.get(
        result["category"], ROUTE_BANDS["GENERAL"]
    )
    return (
        band_html(kind, title, detail),
        notice_html(result["category"], result.get("email_status", "")),
        gr.update(value=result["answer"], visible=True),
        result["image_description"],
    )


def reset():
    return (
        "",
        None,
        EMPTY_BAND,
        "",
        gr.update(value="", visible=False),
        "",
    )


with gr.Blocks(title="Assistant cybersécurité") as demo:
    gr.HTML(HEADER_HTML)

    with gr.Row(equal_height=False):
        with gr.Column(scale=5):
            text_input = gr.Textbox(
                label="Décrivez la situation",
                lines=7,
                placeholder=(
                    "Exemple : un collaborateur a cliqué sur un lien dans "
                    "un email suspect et saisi son mot de passe."
                ),
            )
            image_input = gr.Image(
                label="Capture d'écran ou image (facultatif)",
                type="filepath",
                height=220,
            )
            with gr.Row():
                clear = gr.Button("Effacer", variant="secondary", scale=1)
                submit = gr.Button("Lancer l'analyse", variant="primary", scale=2)

            gr.Examples(
                examples=[
                    [
                        "Un collaborateur a cliqué sur un lien dans un email "
                        "se faisant passer pour les RH et a saisi son mot de "
                        "passe sur une fausse page Microsoft 365."
                    ],
                    ["Quelle est la différence entre un IDS et un IPS ?"],
                    ["Peux-tu m'expliquer comment fonctionne la photosynthèse ?"],
                ],
                inputs=text_input,
                label="Exemples à essayer",
            )

        with gr.Column(scale=7):
            band_output = gr.HTML(EMPTY_BAND)
            notice_output = gr.HTML("")
            answer_output = gr.Markdown(
                visible=False, elem_classes=["answer"]
            )
            with gr.Accordion("Texte lu dans l'image", open=False):
                image_desc_output = gr.Textbox(
                    show_label=False,
                    lines=8,
                    interactive=False,
                    elem_classes=["transcription"],
                )

    submit.click(
        run,
        inputs=[text_input, image_input],
        outputs=[
            band_output,
            notice_output,
            answer_output,
            image_desc_output,
        ],
    )
    clear.click(
        reset,
        inputs=None,
        outputs=[
            text_input,
            image_input,
            band_output,
            notice_output,
            answer_output,
            image_desc_output,
        ],
    )


# 12. Serveur web : page ouverte par le bouton "Traitement" de l'email
api = FastAPI()

PAGE_CSS = """
@import url("https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@700&family=Public+Sans:wght@400;500;600&display=swap");
body {
  margin: 0;
  background: #E9EDF2;
  color: #16213A;
  font-family: "Public Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.55;
}
main {
  max-width: 640px;
  margin: 48px auto;
  padding: 28px 28px 32px;
  background: #FBFCFD;
  border: 1px solid #C9D1DC;
  border-radius: 8px;
}
h1 {
  font-family: "Bricolage Grotesque", system-ui, sans-serif;
  font-weight: 700;
  font-size: 1.7rem;
  line-height: 1.15;
  letter-spacing: -0.02em;
  margin: 0 0 16px;
}
.chip {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 0.9rem;
  font-weight: 600;
}
.chip-warn { background: #FBF0D9; color: #7A5410; }
.chip-ok { background: #E6F2EC; color: #1B5E45; }
.quote {
  white-space: pre-wrap;
  border-left: 4px solid #C9D1DC;
  padding: 2px 0 2px 14px;
  margin: 16px 0 24px;
  max-width: 62ch;
}
.btn {
  background: #16213A;
  color: #FFFFFF;
  border: 0;
  border-radius: 6px;
  padding: 11px 22px;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}
.btn:hover { background: #263859; }
.btn:focus-visible { outline: 2px solid #2F5D8C; outline-offset: 2px; }
@media (max-width: 680px) {
  main { margin: 0; border-radius: 0; border-left: 0; border-right: 0; }
}
"""


def html_page(title: str, content_html: str, status_code: int = 200):
    page = (
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        f"<style>{PAGE_CSS}</style></head>"
        f"<body><main><h1>{html.escape(title)}</h1>{content_html}</main></body></html>"
    )
    return HTMLResponse(page, status_code=status_code)


@api.get("/traitement/{token}")
def traitement_page(token: str):
    """Page de confirmation (le clic sur le lien ne modifie rien)."""
    try:
        incident = incidents_collection.find_one({"_id": token})

        if incident is None:
            return html_page(
                "Lien invalide",
                "<p>Aucun incident ne correspond à ce lien.</p>",
                status_code=404,
            )

        if incident.get("statut") == "traité":
            return html_page(
                "Incident déjà traité",
                '<p><span class="chip chip-ok">Traité</span></p>'
                "<p>Cet incident est déjà marqué comme traité.</p>",
            )

        content = incident.get("message") or incident.get(
            "extraction_image", ""
        )
        return html_page(
            "Prise en charge de l'incident",
            '<p><span class="chip chip-warn">Non traité</span></p>'
            f'<div class="quote">{html.escape(content)}</div>'
            '<form method="post">'
            '<button type="submit" class="btn">Confirmer le traitement</button>'
            "</form>",
        )
    except Exception as e:
        return html_page(
            "Base de données injoignable",
            f"<p>Impossible de lire l'incident ({html.escape(type(e).__name__)}). "
            "Vérifiez que MongoDB est démarré, puis rechargez la page.</p>",
            status_code=500,
        )


@api.post("/traitement/{token}")
def traitement_valider(token: str):
    """Passe l'incident du statut 'non traité' à 'traité'."""
    try:
        # Mise à jour atomique : un double clic ne s'applique qu'une fois
        result = incidents_collection.update_one(
            {"_id": token, "statut": "non traité"},
            {"$set": {"statut": "traité", "date_traitement": datetime.now()}},
        )

        if result.modified_count == 1:
            return html_page(
                "Incident traité",
                '<p><span class="chip chip-ok">Traité</span></p>'
                "<p>L'incident est marqué comme traité dans la base de "
                "données.</p>",
            )

        if incidents_collection.find_one({"_id": token}):
            return html_page(
                "Incident déjà traité",
                '<p><span class="chip chip-ok">Traité</span></p>'
                "<p>Cet incident est déjà marqué comme traité.</p>",
            )

        return html_page(
            "Lien invalide",
            "<p>Aucun incident ne correspond à ce lien.</p>",
            status_code=404,
        )
    except Exception as e:
        return html_page(
            "Mise à jour impossible",
            f"<p>Le statut n'a pas été modifié ({html.escape(type(e).__name__)}). "
            "Vérifiez que MongoDB est démarré, puis rechargez la page.</p>",
            status_code=500,
        )


if __name__ == "__main__":
    # Gradio est monté sur le même serveur que les pages /traitement/...
    web_app = gr.mount_gradio_app(api, demo, path="/")
    uvicorn.run(web_app, host=HOST, port=PORT)