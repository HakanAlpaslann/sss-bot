# bot.py — SSS botu (faq.txt'den okur) — Türkçe/aksan güvenli eşleştirme
import unicodedata

def norm(s: str) -> str:
    # Türkçe I/İ düzelt, aksanları kaldır, küçük harfe çevir
    s = s.replace("İ", "I").replace("ı", "i")  # tutarlı yap
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(path="faq.txt") -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                out[norm(k)] = v.strip()
    except FileNotFoundError:
        pass
    return out

FAQ = load_faq()

def find_any(keys: list[str]) -> str | None:
    # keys: "kargo", "iade", "iletisim" gibi normalize edilmiş aramalar
    for k_norm, val in FAQ.items():
        for needle in keys:
            if needle in k_norm:
                return val
    return None

def cevapla(soru: str) -> str:
    s = norm(soru)

    if "kargo" in s:
        val = find_any(["kargo"])
        return "Kargo: " + (val or "Bilgi yok (faq.txt'ye 'Kargo: ...' ekle).")

    if "iade" in s or "geri odeme" in s or "geri ödeme" in s:
        val = find_any(["iade"])
        return "İade: " + (val or "Bilgi yok (faq.txt'ye 'İade: ...' ekle).")

    if "saat" in s or "acik" in s or "açik" in s or "calisma" in s or "çalisma" in s:
        val = find_any(["calisma saatleri", "saatler", "saat"])
        return "Çalışma saatleri: " + (val or "Bilgi yok (faq.txt'ye 'Çalışma Saatleri: ...' ekle).")

    if "iletisim" in s or "iletisime" in s or "mail" in s or "e posta" in s or "e-posta" in s:
        val = find_any(["iletisim"])
        return "İletişim: " + (val or "Bilgi yok (faq.txt'ye 'İletişim: ...' ekle).")

    if "garanti" in s:
        val = find_any(["garanti"])
        return "Garanti: " + (val or "Bilgi yok (faq.txt'ye 'Garanti: ...' ekle).")

    return "Bu bilgi faq.txt içinde yok. Yeni satır ekleyip tekrar dener misin?"

print("SSS botu hazır (faq.txt'den besleniyor). Soru yaz; çıkmak için boş bırak.")
while True:
    q = input("Soru: ").strip()
    if not q:
        break
    print("Cevap:", cevapla(q))
