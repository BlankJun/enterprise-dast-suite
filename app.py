import os
import socket
import ssl
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import markdown
import requests
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client()

st.set_page_config(
    page_title="Enterprise DAST & Attack Surface Suite",
    page_icon="🛡️",
    layout="wide"
)

# ==============================================================================
# VERİTABANI VE KULLANICI / LİMİT YÖNETİMİ
# ==============================================================================

def veritabani_baslat():
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS taramalar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarih TEXT,
            hedef TEXT,
            portlar TEXT,
            ifsa_sayisi INTEGER,
            eksik_baslik_sayisi INTEGER,
            rate_limit TEXT,
            risk_skoru INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kullanicilar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            kalan_hak INTEGER,
            kayit_tarihi TEXT
        )
    """)
    try:
        cursor.execute("ALTER TABLE taramalar ADD COLUMN risk_skoru INTEGER")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

veritabani_baslat()

def eposta_kaydet_ve_hak_ver(email: str) -> tuple[bool, str]:
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    try:
        tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Yeni kullanıcıya 10 hak veriyoruz
        cursor.execute("INSERT INTO kullanicilar (email, kalan_hak, kayit_tarihi) VALUES (?, 10, ?)", (email, tarih))
        conn.commit()
        conn.close()
        return True, "Başarıyla kayıt oldun! +10 tarama hakkı tanımlandı."
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Bu e-posta adresi ile daha önce kayıt olunmuş!"

def kullanici_hak_getir(email: str) -> int:
    if not email:
        return 0
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT kalan_hak FROM kullanicilar WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0

def hak_dusur(email: str):
    if not email:
        return
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE kullanicilar SET kalan_hak = kalan_hak - 1 WHERE email = ? AND kalan_hak > 0", (email,))
    conn.commit()
    conn.close()

# Oturum yönetimi (Session State)
if "misafir_hak" not in st.session_state:
    st.session_state["misafir_hak"] = 5
if "giris_yapilan_email" not in st.session_state:
    st.session_state["giris_yapilan_email"] = None

# ==============================================================================
# YAN MENÜ (SIDEBAR): KULLANIM HAKKI & BUY ME A COFFEE
# ==============================================================================

with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-checked.png", width=64)
    st.subheader("Oturum & Kullanım Hakları")
    
    aktif_email = st.session_state.get("giris_yapilan_email")
    
    if not aktif_email:
        st.info(f"🎁 Misafir Haklarınız: **{st.session_state['misafir_hak']} / 5**")
        st.markdown("---")
        st.write("Daha fazla hak ve sınırsız özellikler için e-postanızla kayıt olun (+10 hak kazan):")
        
        girilen_email = st.text_input("E-Posta Adresiniz", placeholder="ornek@sirket.com")
        if st.button("Kayıt Ol & 10 Hak Kazan", use_container_width=True):
            if "@" in girilen_email and "." in girilen_email:
                basarili, mesaj = eposta_kaydet_ve_hak_ver(girilen_email.strip().lower())
                if basarili:
                    st.session_state["giris_yapilan_email"] = girilen_email.strip().lower()
                    st.success(mesaj)
                    st.rerun()
                else:
                    st.error(mesaj)
            else:
                st.warning("Lütfen geçerli bir e-posta adresi girin.")
    else:
        kalan = kullanici_hak_getir(aktif_email)
        st.success(f"Oturum Açık:\n`{aktif_email}`")
        st.metric(label="🎯 Kalan Tarama Hakkınız", value=kalan)
    
    st.markdown("---")
    st.markdown("### ☕ Projeyi Destekle")
    st.markdown("Bu açık kaynaklı güvenlik aracını geliştirmemize ve sunucu maliyetlerine destek olmak ister misiniz?")
    st.markdown(
        '<a href="https://www.buymeacoffee.com" target="_blank"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=blankjun&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>',
        unsafe_allow_html=True
    )

# ==============================================================================
# VERİTABANI VE GEÇMİŞ (DIFF) YÖNETİMİ
# ==============================================================================

def gecmisi_kaydet(hedef: str, portlar: list, ifsa_sayisi: int, baslik_sayisi: int, rate_durum: str, risk_skoru: int):
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_str = ", ".join(portlar)
    cursor.execute("""
        INSERT INTO taramalar (tarih, hedef, portlar, ifsa_sayisi, eksik_baslik_sayisi, rate_limit, risk_skoru)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tarih, hedef, port_str, ifsa_sayisi, baslik_sayisi, rate_durum, risk_skoru))
    conn.commit()
    conn.close()

def onceki_taramayi_getir(hedef: str) -> dict:
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT tarih, portlar, ifsa_sayisi, eksik_baslik_sayisi, rate_limit, risk_skoru 
        FROM taramalar WHERE hedef = ? ORDER BY id DESC LIMIT 1 OFFSET 1
    """, (hedef,))
    kayit = cursor.fetchone()
    conn.close()
    
    if kayit:
        skor = kayit[5] if len(kayit) > 5 and kayit[5] is not None else 0
        return {
            "tarih": kayit[0],
            "portlar": [p.strip() for p in kayit[1].split(",") if p.strip()],
            "ifsa_sayisi": kayit[2],
            "eksik_baslik_sayisi": kayit[3],
            "rate_limit": kayit[4],
            "risk_skoru": skor
        }
    return None

# ==============================================================================
# RİSK SKORU HESAPLAMA MOTORU
# ==============================================================================

def risk_skoru_hesapla(acik_portlar: list, ifsa_sayisi: int, eksik_baslik_sayisi: int, rate_durum: str, cors_durum: str) -> int:
    skor = 0
    if "Kritik port saptanmadı" not in acik_portlar[0]:
        skor += len(acik_portlar) * 12
    skor += ifsa_sayisi * 30
    skor += eksik_baslik_sayisi * 5
    if "Savunmasız" in rate_durum:
        skor += 15
    if cors_durum != "Yok":
        skor += 20
    return min(skor, 100)

# ==============================================================================
# YEREL DENETİM & SALDIRI YÜZEYİ (ASM) MOTORLARI
# ==============================================================================

def port_ve_servis_tara(url: str) -> list:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    
    kritik_portlar = [
        (20, "FTP-Data"), (21, "FTP"), (22, "SSH"), (23, "Telnet"),
        (53, "DNS"), (80, "HTTP"), (443, "HTTPS"), (3306, "MySQL"),
        (3389, "RDP"), (5432, "PostgreSQL"), (6379, "Redis"),
        (8080, "HTTP-Proxy"), (27017, "MongoDB")
    ]
    
    aciklar = []
    def port_kontrol(hedef_port):
        port, servis = hedef_port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((host, port)) == 0:
                    return f"Port {port} ({servis})"
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        sonuclar = list(ex.map(port_kontrol, kritik_portlar))
    
    aciklar = [s for s in sonuclar if s]
    return aciklar if aciklar else ["Kritik port saptanmadı (Filtreli)."]

def alt_alan_adi_kesif(url: str) -> str:
    temiz_host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    parcalar = temiz_host.split(".")
    kok_domain = ".".join(parcalar[-2:]) if len(parcalar) >= 2 else temiz_host

    adaylar = ["api", "dev", "test", "staging", "admin", "panel", "portal", "mail", "auth", "vpn"]
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

def hassas_dosya_denetle(url: str) -> list:
    if not url.startswith("http"):
        url = "https://" + url
    base = url.rstrip("/")
    kritik_yollar = ["/.env", "/.git/HEAD", "/config.json", "/docker-compose.yml", "/backup.sql"]

    def dosya_iste(yol):
        try:
            r = requests.get(f"{base}{yol}", timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                return f"{yol} (200 OK)"
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=5) as ex:
        sonuclar = list(ex.map(dosya_iste, kritik_yollar))
    return [s for s in sonuclar if s]

def cors_ve_metot_denetle(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    sonuc = {"cors_zafiyeti": "Yok", "acik_metotlar": []}
    try:
        r = requests.get(url, headers={"Origin": "https://attacker-site.com"}, timeout=4, verify=False)
        if r.headers.get("Access-Control-Allow-Origin") in ["https://attacker-site.com", "*"]:
            sonuc["cors_zafiyeti"] = "Güvensiz Origin İzni"
    except Exception:
        pass
    for m in ["OPTIONS", "PUT", "DELETE"]:
        try:
            r = requests.request(m, url, timeout=3, verify=False)
            if r.status_code in [200, 204]:
                sonuc["acik_metotlar"].append(m)
        except Exception:
            pass
    return sonuc

def baslik_ve_tls_denetle(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    veriler = {"eksik_basliklar": [], "sertifika_durum": "Bilinmiyor"}
    kritikler = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
    try:
        r = requests.get(url, timeout=5, verify=False)
        for k in kritikler:
            if k not in r.headers:
                veriler["eksik_basliklar"].append(k)
    except Exception:
        pass
    return veriler

def rate_limit_hizli_olc(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    engellendi = 0
    def istek_at():
        nonlocal engellendi
        try:
            r = requests.head(url, timeout=1.5, allow_redirects=False)
            if r.status_code in [429, 403]:
                engellendi += 1
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda _: istek_at(), range(20)))
    return f"Aktif Eşik ({engellendi}/20 Blok)" if engellendi > 0 else "Savunmasız (0 Blok)"

def savunma_yamasi_uret(url: str) -> str:
    alan = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return f"""```nginx
# /etc/nginx/conf.d/{alan}.conf
server {{
    server_name {alan};
    location ~* /\\.(env|git) {{ deny all; return 404; }}
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
}}
```"""

def html_rapor_olustur(hedef: str, markdown_metni: str, yama_metni: str, risk_skoru: int) -> str:
    govde = markdown.markdown(markdown_metni + f"\n\n### Kurumsal Risk Skoru: {risk_skoru}/100\n" + "\n\n### Savunma Yaması\n" + yama_metni, extensions=['tables', 'fenced_code'])
    return f"<!DOCTYPE html><html><body><h1>Güvenlik Raporu - {hedef}</h1>{govde}</body></html>"

# ==============================================================================
# STREAMLIT ARAYÜZÜ
# ==============================================================================

st.title("🛡️ Enterprise DAST & Attack Surface Scanner")
st.markdown("Hassas dosya sızıntıları, açık servisler ve risk skoru analizi yapan otonom güvenlik suite'i.")

# Hak Kontrol Mantığı
aktif_email = st.session_state.get("giris_yapilan_email")
hak_bitti = False

if aktif_email:
    kalan = kullanici_hak_getir(aktif_email)
    if kalan <= 0:
        hak_bitti = True
        st.warning("⚠️ Tarama hakkınız kalmadı! Daha fazla tarama için lütfen ek paketleri inceleyin.")
else:
    if st.session_state["misafir_hak"] <= 0:
        hak_bitti = True
        st.warning("🎁 Ücretsiz 5 misafir hakkınız bitti! Sınırsız tarama ve +10 hak için soldaki menüden e-postanızla kayıt olun.")

col1, col2 = st.columns([4, 1])
with col1:
    hedef_url = st.text_input("Hedef Alan Adı veya URL", placeholder="örnek: scanme.nmap.org", disabled=hak_bitti)
with col2:
    st.write("")
    st.write("")
    tara = st.button("Tam Denetimi Başlat", use_container_width=True, type="primary", disabled=hak_bitti)

if tara and hedef_url and not hak_bitti:
    # Hak düşürme işlemi
    if aktif_email:
        hak_dusur(aktif_email)
    else:
        st.session_state["misafir_hak"] -= 1

    bar = st.progress(0, text="Denetim başlatılıyor...")
    
    bar.progress(20, text="[1/4] Alt alan adları taranıyor...")
    sublar = alt_alan_adi_kesif(hedef_url)

    bar.progress(40, text="[2/4] Kritik portlar ve servisler taranıyor (ASM)...")
    acik_portlar = port_ve_servis_tara(hedef_url)

    bar.progress(60, text="[3/4] Hassas dosyalar, CORS ve başlıklar denetleniyor...")
    ifsa_dosyalar = hassas_dosya_denetle(hedef_url)
    cors_sonuc = cors_ve_metot_denetle(hedef_url)
    basliklar = baslik_ve_tls_denetle(hedef_url)
    rate_durum = rate_limit_hizli_olc(hedef_url)

    bar.progress(80, text="[4/4] Risk skoru hesaplanıyor ve veritabanına kaydediliyor...")
    hesaplanan_skor = risk_skoru_hesapla(
        acik_portlar, 
        len(ifsa_dosyalar), 
        len(basliklar.get("eksik_basliklar", [])), 
        rate_durum, 
        cors_sonuc.get("cors_zafiyeti", "Yok")
    )
    
    gecmisi_kaydet(hedef_url, acik_portlar, len(ifsa_dosyalar), len(basliklar.get("eksik_basliklar", [])), rate_durum, hesaplanan_skor)
    onceki_kayit = onceki_taramayi_getir(hedef_url)

    portlar_md = "\n".join([f"* {p}" for p in acik_portlar])
    eksik_basliklar_str = ", ".join(basliklar.get('eksik_basliklar', [])) or 'Yok'

    rapor = f"""# 🛡️ GÜVENLİK DENETİM VE SALDIRI YÜZEYİ RAPORU
**Hedef:** `{hedef_url}`

### 🚨 Kurumsal Risk Skoru: **{hesaplanan_skor} / 100**

### 1. Dışa Açık Portlar ve Servisler
{portlar_md}

### 2. Zafiyet Analizi Öngörüsü
* **Hassas Dosya İfşası:** {len(ifsa_dosyalar)} kritik dosya tespit edildi.
* **CORS Durumu:** {cors_sonuc.get('cors_zafiyeti')}
* **Eksik Güvenlik Başlıkları:** {eksik_basliklar_str}
* **Rate Limiting Durumu:** {rate_durum}

### 3. Keşfedilen Alt Alan Adları
```text
{sublar}
```"""

    yama = savunma_yamasi_uret(hedef_url)
    bar.progress(100, text="Denetim tamamlandı!")

    st.session_state["son_hedef"] = hedef_url
    st.session_state["son_rapor"] = rapor
    st.session_state["son_yama"] = yama
    st.session_state["onceki_kayit"] = onceki_kayit
    st.session_state["simdiki_portlar"] = acik_portlar
    st.session_state["simdiki_ifsa"] = len(ifsa_dosyalar)
    st.session_state["simdiki_baslik"] = len(basliklar.get("eksik_basliklar", []))
    st.session_state["simdiki_skor"] = hesaplanan_skor
    st.rerun()

if "son_rapor" in st.session_state:
    skor_val = st.session_state.get("simdiki_skor", 0)
    delta_val = None
    onceki = st.session_state.get("onceki_kayit")
    if onceki:
        fark = skor_val - onceki.get("risk_skoru", 0)
        delta_val = f"{fark:+d} puan"

    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.metric(label="📊 Kurumsal Risk Skoru", value=f"{skor_val} / 100", delta=delta_val, delta_color="inverse")
    with col_m2:
        st.metric(label="⚠️ Tespit Edilen Hassas Dosya", value=st.session_state.get("simdiki_ifsa", 0))
    with col_m3:
        st.metric(label="🔒 Eksik Güvenlik Başlığı", value=st.session_state.get("simdiki_baslik", 0))

    st.markdown("---")

    tab1, tab2, tab3, tab4 = st.tabs(["📑 Denetim Raporu", "🛠️ Savunma Yaması", "📈 Geçmiş & Diff", "💾 İndir"])
    
    with tab1:
        st.markdown(st.session_state["son_rapor"])

    with tab2:
        st.markdown(st.session_state["son_yama"])

    with tab3:
        st.subheader("📊 Zaman Bazlı Değişim ve Regresyon Takibi (Diff Engine)")
        if onceki:
            st.info(f"Karşılaştırılan Önceki Tarama Tarihi: **{onceki['tarih']}**")
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Önceki Durum:**")
                st.write(f"- Risk Skoru: `{onceki.get('risk_skoru', 0)} / 100`")
                st.write(f"- Açık Portlar: `{', '.join(onceki.get('portlar', []))}`")
                st.write(f"- Hassas Dosya: `{onceki.get('ifsa_sayisi', 0)}`")
            with col2:
                st.write("**Mevcut Durum:**")
                st.write(f"- Risk Skoru: `{st.session_state.get('simdiki_skor', 0)} / 100`")
                st.write(f"- Açık Portlar: `{', '.join(st.session_state.get('simdiki_portlar', []))}`")
                st.write(f"- Hassas Dosya: `{st.session_state.get('simdiki_ifsa', 0)}`")
            
            st.markdown("---")
            skor_fark = st.session_state.get('simdiki_skor', 0) - onceki.get('risk_skoru', 0)
            if skor_fark > 0:
                st.error(f"⚠️ **Güvenlik Seviyesi Kötüleşti:** Risk skoru {skor_fark} puan arttı!")
            elif skor_fark < 0:
                st.success(f"✅ **Güvenlik İyileşti:** Risk skoru {abs(skor_fark)} puan düştü.")
            else:
                st.info("Risk skorunda değişim saptanmadı.")
        else:
            st.warning("Bu hedef için önceki tarama kaydı bulunamadı. İkinci taramadan itibaren skor değişim analizi aktifleşecektir.")

    with tab4:
        html_kod = html_rapor_olustur(st.session_state["son_hedef"], st.session_state["son_rapor"], st.session_state["son_yama"], st.session_state.get("simdiki_skor", 0))
        st.download_button("📄 HTML Raporunu İndir", data=html_kod, file_name="rapor.html", mime="text/html", type="primary")