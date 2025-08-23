# api.py — multi-tenant (çok müşterili) SSS Bot + WhatsApp Cloud API webhook
import os
import unicodedata
import requests
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="SSS API")

# ----- CORS -----
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),  # prod'da domain'lerini yaz
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Yardımcılar =====
def norm(s: str) -> str:
    """Türkçe karakterleri normalize eder, küçük harfe çevirir."""
    s = s.replace("İ", "I").replace("ı", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(client: str) -> dict[str, str]:
    """Belirtilen müşterinin faq.txt dosyasını okur."""
    path = Path(f"data/{client}/faq.txt")
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[norm(k)] = v.strip()
    return out

def find_any(faq: dict[str, str], keys: list[str]) -> str | None:
    """faq içinden anahtar kelimeleri bulur."""
    for k_norm, val in faq.items():
        for needle in keys:
            if needle in k_norm:
                return val
    return None

def answer(client: str, question: str) -> str:
    """Soruya göre cevap döner."""
    faq = load_faq(client)
    s = norm(question)

    if "kargo" in s:
        return "Kargo: " + (find_any(faq, ["kargo"]) or "Bilgi yok.")
    if "iade" in s:
        return "İade: " + (find_any(faq, ["iade"]) or "Bilgi yok.")
    if any(w in s for w in ["saat", "acik", "açik", "calisma", "çalisma"]):
        return "Çalışma saatleri: " + (
            find_any(faq, ["calisma saatleri", "saatler", "saat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["iletisim", "iletişim", "mail", "e posta", "e-posta"]):
        return "İletişim: " + (find_any(faq, ["iletisim"]) or "Bilgi yok.")
    if "garanti" in s:
        return "Garanti: " + (find_any(faq, ["garanti"]) or "Bilgi yok.")
    if any(w in s for w in ["ucret", "ücret", "fiyat"]):
        return "Ücret: " + (
            find_any(faq, ["servis ücreti", "ucret", "fiyat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["bölge", "bolge", "nerelere", "servis alani"]):
        return "Hizmet bölgeleri: " + (
            find_any(
                faq,
                [
                    "hangi bolgelerde hizmet veriyorsunuz",
                    "bolgeler",
                    "bölgeler",
                    "servis bolgesi",
                ],
            )
            or "Bilgi yok."
        )

    # if'lerin hiçbiri tetiklenmediyse:
    return "Bu bilgi faq.txt içinde yok."

# ===== HTTP API =====
class AskIn(BaseModel):
    client: str      # ör: "dayi", "musteriA"
    question: str    # soru

@app.get("/")
def root():
    return {"message": "SSS Bot API. Test: /docs  |  Soru: POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}

# ===== WhatsApp Cloud API entegrasyonu =====
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")          # Meta token
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID", "")    # Phone Number ID
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "verify-me")
DEFAULT_CLIENT = os.getenv("DEFAULT_CLIENT", "dayi")       # şimdilik dayı'ya yönlendir

def send_whatsapp_text(to_wa_id: str, text: str):
    """Gönderene WhatsApp üzerinden metin mesajı yolla."""
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_ID):
        print("WhatsApp env vars missing")
        return
    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code >= 400:
        print("WA send error:", r.status_code, r.text)

# 1) Meta doğrulama (hub.* parametre adlarına dikkat)
@app.get("/whatsapp/webhook")
def wa_verify(request: Request):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")
    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(challenge or "")
    raise HTTPException(status_code=403, detail="verification failed")

# 2) Mesaj alma (Webhook POST)
@app.post("/whatsapp/webhook")
async def wa_receive(request: Request):
    data = await request.json()
    try:
        entry = data["entry"][0]["changes"][0]["value"]
        messages = entry.get("messages")
        if not messages:
            return {"ok": True}  # status/read vb. olabilir

        msg = messages[0]
        wa_id = msg["from"]                                # gönderen tel (ülke kodlu)
        text = msg.get("text", {}).get("body", "").strip() # gelen mesaj

        # İleride numara->müşteri eşlemesi yapabiliriz:
        # NUMBER_TO_CLIENT = {"90555XXXXXXX": "dayi", "90506YYYYYYY": "musteriA"}
        # client = NUMBER_TO_CLIENT.get(wa_id, DEFAULT_CLIENT)
        client = DEFAULT_CLIENT

        reply = answer(client, text)
        send_whatsapp_text(wa_id, reply)
    except Exception as e:
        print("WA parse error:", e)
    return {"ok": True}
