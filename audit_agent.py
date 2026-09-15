import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from google import genai
from google.genai import types
import requests

load_dotenv()
client = genai.Client()

# ==============================================================================
# YEREL DENETİM FONKSİYONLARI (SIFIR API TÜKETİMİ)
# ==============================================================================

def alt_alan_adi_kesif(url: str) -> str:
    temiz_host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    parcalar = temiz_host.split(".")
    kok_domain = ".".join(parcalar[-2:]) if len(parcalar) >= 2 else temiz_host

    adaylar = ["api", "dev", "test", "staging", "admin", "panel", "portal", "mail", "auth", "vpn"]
    bulunanlar = []

    def sorgula(sub):
        tam = f"{sub}.{kok_domain}"
        try:
            ip = socket.gethostbyname(tam)
            return f"{tam} -> {ip}"
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        sonuclar = list(ex.map(sorgula, adaylar))
    
    bulunanlar = [s for s in sonuclar if s]
    return "\n".join(bulunanlar) if bulunanlar else "Yaygın alt alan adı tespit edilemedi."


def baslik_ve_tls_denetle(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    veriler = {"server": "Gizli", "x_powered_by": "Yok", "eksik_basliklar": [], "mevcut_basliklar": []}
    kritikler = [
        "Strict-Transport-Security", "Content-Security-Policy", 
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
    ]

    try:
        r = requests.get(url, timeout=5, verify=False)
        veriler["server"] = r.headers.get("Server", "Gizli")
        veriler["x_powered_by"] = r.headers.get("X-Powered-By", "Yok")

        for k in kritikler:
            if k in r.headers:
                veriler["mevcut_basliklar"].append(f"{k}: {r.headers[k]}")
            else:
                veriler["eksik_basliklar"].append(k)
    except Exception as e:
        veriler["hata"] = str(e)

    return veriler


def metot_ve_hata_denetle(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    cikti = {"acik_metotlar": [], "hata_sizintisi": "Yok"}
    for m in ["OPTIONS", "PUT", "DELETE"]:
        try:
            r = requests.request(m, url, timeout=3, verify=False)
            if r.status_code in [200, 204]:
                cikti["acik_metotlar"].append(f"{m} (Kod: {r.status_code})")
        except Exception:
            pass

    test_url = url.rstrip("/") + "/guvenlik_denetim_404_test"
    try:
        r = requests.get(test_url, timeout=3, verify=False)
        if any(h in r.text for h in ["Traceback", "Exception", "Django", "Werkzeug"]):
            cikti["hata_sizintisi"] = f"Açık Hata Detayı Sızıyor! (Kod: {r.status_code})"
    except Exception:
        pass

    return cikti


def rate_limit_hizli_olc(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url

    engellendi = 0
    basarili = 0

    def istek_at():
        nonlocal engellendi, basarili
        try:
            r = requests.head(url, timeout=1.5, allow_redirects=False)
            if r.status_code in [429, 403]:
                engellendi += 1
            else:
                basarili += 1
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(lambda _: istek_at(), range(30)))

    if engellendi > 0:
        return f"Aktif Eşik Bulundu (30 İstekte {engellendi} Adet Bloklandı)"
    return "30 Eşzamanlı İstekte Engel Tetiklenmedi (Savunmasız)"


def savunma_yamasi_uret(url: str) -> str:
    alan = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return f"""
================================================================================
🛠️ DİNAMİK ALTYAPI SAVUNMA YAMASI (AUTO-PATCH)
Hedef: {alan}
================================================================================
[NGINX SIKILAŞTIRMA - /etc/nginx/conf.d/{alan}.conf]
limit_req_zone $binary_remote_addr zone={alan.replace('.', '_')}_zone:10m rate=10r/s;

server {{
    server_name {alan};

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline'; frame-ancestors 'none';" always;

    if ($request_method !~ ^(GET|POST|HEAD)$ ) {{
        return 405;
    }}

    location / {{
        limit_req zone={alan.replace('.', '_')}_zone burst=15 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8000; # Uygulama Portu
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
================================================================================
"""

# ==============================================================================
# ANA AKIŞ (TEK SEFERLİK AI ÇAĞRISI)
# ==============================================================================

if __name__ == "__main__":
    while True:
        hedef = input("\nDenetlenecek web adresi (Çıkış için 'q'): ").strip()
        if hedef.lower() == "q" or not hedef:
            print("Ajan kapatıldı.")
            break

        print(f"\n[1/4] Yerel keşifler başlatılıyor: {hedef}...")
        sublar = alt_alan_adi_kesif(hedef)
        
        print("[2/4] Başlık ve şifreleme denetleniyor...")
        basliklar = baslik_ve_tls_denetle(hedef)
        
        print("[3/4] HTTP metot ve hız sınırları test ediliyor...")
        metotlar = metot_ve_hata_denetle(hedef)
        rate_durum = rate_limit_hizli_olc(hedef)

        # Tüm veriyi tek bir pakette topla
        denetim_ozeti = f"""
Hedef: {hedef}
Açık Varlık / Subdomainler:
{sublar}

Sunucu & Güvenlik Başlıkları:
- Sunucu Bilgisi: {basliklar.get('server')}
- Teknoloji: {basliklar.get('x_powered_by')}
- Eksik Başlıklar: {', '.join(basliklar.get('eksik_basliklar', []))}
- Mevcut Başlıklar: {', '.join(basliklar.get('mevcut_basliklar', []))}

İstek & Metot Denetimleri:
- Tehlikeli Açık Metotlar: {', '.join(metotlar.get('acik_metotlar', [])) or 'Temiz'}
- Teknik Hata Sızıntısı: {metotlar.get('hata_sizintisi')}
- Rate Limit Durumu: {rate_durum}
"""

        print("[4/4] Gemini tek istek ile konsolide raporu üretiyor...")
        try:
            prompt = f"""
Sen Kıdemli bir Güvenlik ve Sistem Mimarı'sın. Aşağıdaki DAST ve altyapı tarama verilerini kullanarak kurumsal, net bir Güvenlik Denetim Raporu hazırla.

TARAMA VERİLERİ:
{denetim_ozeti}

RAPOR FORMATI:
1. Yönetici Özeti (Genel Risk Skoru 1-10)
2. Keşfedilen Dış Varlıklar ve Subdomain Analizi
3. Detaylı Zafiyet Matrisi (OWASP kategorileri ve kanıtlar ile)
4. Rol Bazlı Savunma Reçetesi (DevOps, Geliştirici ve Ürün Yöneticisi için)
"""
            cevap = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt
            )

            yama = savunma_yamasi_uret(hedef)

            print("\n" + "=" * 60)
            print("📑 OTOMATİZE GÜVENLİK VE ALTYAPI DENETİM RAPORU")
            print("=" * 60)
            print(cevap.text)
            print(yama)

            dosya_adi = f"rapor_{hedef.replace('https://', '').replace('http://', '').replace('/', '_')}.md"
            with open(dosya_adi, "w", encoding="utf-8") as f:
                f.write(cevap.text + "\n\n" + yama)
            print(f"\n[+] Rapor diske kaydedildi: {dosya_adi}")

        except Exception as e:
            print(f"\n[!] Rapor oluşturulurken hata: {str(e)}")