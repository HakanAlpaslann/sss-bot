# api.py — multi-tenant (çok müşterili) SSS Bot
import os, unicodedata
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SSS API")

# CORS: farklı sitelerden çağrı yapılabilsin
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Yardımcılar ----
def norm(s: str) -> str:
    """Türkçe karakterleri normalize eder, küçük harfe çevirir"""
    s = s.replace("İ","I").replace("ı","i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(client: str) -> dict[str,str]:
    """Belirtilen müşterinin faq.txt dosyasını okur"""
    path = Path(f"data/{client}/faq.txt")
    out: dict[str,str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[norm(k)] = v.strip()
    return out

def find_any(faq: dict[str,str], keys: list[str]) -> str|None:
    """faq içinden anahtar kelimeleri bulur"""
    for k_norm, val in faq.items():
        for needle in keys:
            if needle in k_norm:
                return val
    return None

def answer(client: str, question: str) -> str:
    """Soruya göre cevap döner"""
    faq = load_faq(client)
    s = norm(question)

    if "kargo" in s:
        return "Kargo: " + (find_any(faq,["kargo"]) or "Bilgi yok.")
    if "iade" in s:
        return "İade: " + (find_any(faq,["iade"]) or "Bilgi yok.")
    if any(w in s for w in ["saat","acik","açik","calisma","çalisma"]):
        return "Çalışma saatleri: " + (find_any(faq,["calisma saatleri","saatler","saat"]) or "Bilgi yok.")
    if any(w in s for w in ["iletisim","iletişim","mail","e posta","e-posta"]):
        return "İletişim: " + (find_any(faq,["iletisim"]) or "Bilgi yok.")
    if "garanti" in s:
        return "Garanti: " + (find_any(faq,["garanti"]) or "Bilgi yok.")
    if any(w in s for w in ["ucret","ücret","fiyat"]):
        return "Ücret: " + (find_any(faq,["servis ücreti","ucret","fiyat"]) or "Bilgi yok.")
    if any(w in s for w in ["bölge","bolge","nerelere","servis alani"]):
        return "Hizmet bölgeleri: " + (find_any(faq,["hangi bolgelerde hizmet veriyorsunuz","bolgeler","bölgeler","servis bolgesi"]) or "Bilgi yok.")

    return "Bu bilgi faq.txt içinde yok."

# ---- API ----
class AskIn(BaseModel):
    client: str      # hangi müşteri? (ör: "dayi", "musteriA")
    question: str    # soru

@app.get("/")
def root():
    return {"message": "SSS Bot API. Test için /docs, soru için POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}
