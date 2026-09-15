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
# ÇOKLU DİL (I18N) SÖZLÜĞÜ
# ==============================================================================

METINLER = {
    "Türkçe": {
        "title": "🛡️ Kurumsal DAST ve Saldırı Yüzeyi Tarayıcısı",
        "subtitle": "Hassas dosya sızıntıları, açık servisler ve risk skoru analizi yapan otonom güvenlik suite'i.",
        "sidebar_auth_title": "Oturum & Kullanım Hakları",
        "guest_rights": "🎁 Misafir Haklarınız",
        "no_rights_warning": "⚠️ Tarama hakkınız kalmadı! Lütfen yeni bir oturum açın.",
        "guest_exhausted_warning": "🎁 Ücretsiz 5 misafir hakkınız bitti! Devam etmek için soldaki menüden e-postanızla kayıt olun (+10 hak kazanın).",
        "email_label": "E-Posta Adresiniz",
        "email_placeholder": "ornek@sirket.com",
        "register_btn": "Kayıt Ol & 10 Hak Kazan",
        "invalid_email": "Lütfen geçerli bir e-posta adresi girin.",
        "session_active": "Oturum Açık",
        "remaining_rights": "🎯 Kalan Tarama Hakkınız",
        "support_title": "🌟 Projeyi Destekle",
        "support_desc": "Üretmekten büyük keyif alıyorum! Çalışmalarımın devam etmesini istiyorsanız projeyi **GitHub'da yıldızlayarak (Star)** ve paylaşarak destek olabilirsiniz.",
        "support_thanks": "🚀 *Desteğiniz ve katkınız için teşekkürler!*",
        "target_input": "Hedef Alan Adı veya URL",
        "target_placeholder": "örnek: scanme.nmap.org",
        "start_audit": "Tam Denetimi Başlat",
        "audit_start": "Denetim başlatılıyor...",
        "step_1": "[1/4] Alt alan adları taranıyor...",
        "step_2": "[2/4] Kritik portlar ve servisler taranıyor (ASM)...",
        "step_3": "[3/4] Hassas dosyalar, CORS ve başlıklar denetleniyor...",
        "step_4": "[4/4] Risk skoru hesaplanıyor ve veritabanına kaydediliyor...",
        "audit_complete": "Denetim tamamlandı!",
        "metric_score": "📊 Kurumsal Risk Skoru",
        "metric_file": "⚠️ Tespit Edilen Hassas Dosya",
        "metric_header": "🔒 Eksik Güvenlik Başlığı",
        "tab_report": "📑 Denetim Raporu",
        "tab_patch": "🛠️ Savunma Yaması",
        "tab_history": "📈 Geçmiş & Diff",
        "tab_download": "💾 İndir",
        "download_btn": "📄 HTML Raporunu İndir",
        "no_history": "Bu hedef için önceki tarama kaydı bulunamadı. İkinci taramadan itibaren skor değişim analizi aktifleşecektir.",
        "history_title": "📊 Zaman Bazlı Değişim ve Regresyon Takibi (Diff Engine)",
        "previous_scan_date": "Karşılaştırılan Önceki Tarama Tarihi",
        "previous_status": "**Önceki Durum:**",
        "current_status": "**Mevcut Durum:**",
        "risk_worse": "⚠️ **Güvenlik Seviyesi Kötüleşti:** Risk skoru {fark} puan arttı!",
        "risk_better": "✅ **Güvenlik İyileşti:** Risk skoru {fark} puan düştü.",
        "risk_same": "Risk skorunda değişim saptanmadı.",
        "report_header": "# 🛡️ GÜVENLİK DENETİM VE SALDIRI YÜZEYİ RAPORU",
        "target_label": "**Hedef:**",
        "score_label": "### 🚨 Kurumsal Risk Skoru:",
        "ports_title": "### 1. Dışa Açık Portlar ve Servisler",
        "vuln_title": "### 2. Zafiyet Analizi Öngörüsü",
        "vuln_file": "* **Hassas Dosya İfşası:** {count} kritik dosya tespit edildi.",
        "vuln_cors": "* **CORS Durumu:** {status}",
        "vuln_headers": "* **Eksik Güvenlik Başlıkları:** {headers}",
        "vuln_rate": "* **Rate Limiting Durumu:** {rate}",
        "subdomains_title": "### 3. Keşfedilen Alt Alan Adları",
        "defense_title": "### Savunma Yaması"
    },
    "English": {
        "title": "🛡️ Enterprise DAST & Attack Surface Scanner",
        "subtitle": "Autonomous security suite for sensitive file leaks, open services, and risk score analysis.",
        "sidebar_auth_title": "Session & Usage Rights",
        "guest_rights": "🎁 Guest Rights",
        "no_rights_warning": "⚠️ You have no scan rights left! Please start a new session.",
        "guest_exhausted_warning": "🎁 Your 5 free guest rights have ended! Register with your email from the left menu to continue (+10 rights).",
        "email_label": "Your Email Address",
        "email_placeholder": "example@company.com",
        "register_btn": "Register & Get 10 Rights",
        "invalid_email": "Please enter a valid email address.",
        "session_active": "Session Active",
        "remaining_rights": "🎯 Remaining Scan Rights",
        "support_title": "🌟 Support the Project",
        "support_desc": "I truly enjoy creating! If you'd like to support me and keep my work going, you can star and share the project on **GitHub**.",
        "support_thanks": "🚀 *Thank you for your support and contribution!*",
        "target_input": "Target Domain or URL",
        "target_placeholder": "example: scanme.nmap.org",
        "start_audit": "Start Full Audit",
        "audit_start": "Starting audit...",
        "step_1": "[1/4] Scanning subdomains...",
        "step_2": "[2/4] Scanning critical ports and services (ASM)...",
        "step_3": "[3/4] Inspecting sensitive files, CORS, and headers...",
        "step_4": "[4/4] Calculating risk score and saving to database...",
        "audit_complete": "Audit completed!",
        "metric_score": "📊 Enterprise Risk Score",
        "metric_file": "⚠️ Sensitive Files Found",
        "metric_header": "🔒 Missing Security Header",
        "tab_report": "📑 Audit Report",
        "tab_patch": "🛠️ Defense Patch",
        "tab_history": "📈 History & Diff",
        "tab_download": "💾 Download",
        "download_btn": "📄 Download HTML Report",
        "no_history": "No previous scan record found for this target. Score change analysis will be active starting from the second scan.",
        "history_title": "📊 Time-Based Change and Regression Tracking (Diff Engine)",
        "previous_scan_date": "Compared Previous Scan Date",
        "previous_status": "**Previous Status:**",
        "current_status": "**Current Status:**",
        "risk_worse": "⚠️ **Security Level Worsened:** Risk score increased by {fark} points!",
        "risk_better": "✅ **Security Improved:** Risk score decreased by {fark} points.",
        "risk_same": "No change detected in the risk score.",
        "report_header": "# 🛡️ SECURITY AUDIT AND ATTACK SURFACE REPORT",
        "target_label": "**Target:**",
        "score_label": "### 🚨 Enterprise Risk Score:",
        "ports_title": "### 1. Externally Exposed Ports and Services",
        "vuln_title": "### 2. Vulnerability Analysis Prediction",
        "vuln_file": "* **Sensitive File Disclosure:** {count} critical files detected.",
        "vuln_cors": "* **CORS Status:** {status}",
        "vuln_headers": "* **Missing Security Headers:** {headers}",
        "vuln_rate": "* **Rate Limiting Status:** {rate}",
        "subdomains_title": "### 3. Discovered Subdomains",
        "defense_title": "### Defense Patch"
    }
}

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

def eposta_kaydet_ve_hak_ver(email: str, dil: str) -> tuple[bool, str]:
    conn = sqlite3.connect("dast_history.db")
    cursor = conn.cursor()
    try:
        tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO kullanicilar (email, kalan_hak, kayit_tarihi) VALUES (?, 10, ?)", (email, tarih))
        conn.commit()
        conn.close()
        msg = "Başarıyla kayıt oldun! +10 tarama hakkı tanımlandı." if dil == "Türkçe" else "Successfully registered! +10 scan rights granted."
        return True, msg
    except sqlite3.IntegrityError:
        conn.close()
        msg = "Bu e-posta adresi ile daha önce kayıt olunmuş!" if dil == "Türkçe" else "This email address is already registered!"
        return False, msg

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
# YAN MENÜ (SIDEBAR): DİL SEÇİMİ, KULLANIM HAKKI & TOPLULUK DESTEĞİ
# ==============================================================================

with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-checked.png", width=64)
    
    # Dil Seçimi
    secilen_dil = st.selectbox("🌐 Dil / Language", ["Türkçe", "English"], index=0)
    t = METINLER[secilen_dil]
    
    st.markdown("---")
    st.subheader(t["sidebar_auth_title"])
    
    aktif_email = st.session_state.get("giris_yapilan_email")
    
    if not aktif_email:
        st.info(f"{t['guest_rights']}: **{st.session_state['misafir_hak']} / 5**")
        st.markdown("---")
        st.write(t["guest_exhausted_warning"] if secilen_dil == "Türkçe" else "Register with your email from the left menu for more rights (+10 rights):")
        
        girilen_email = st.text_input(t["email_label"], placeholder=t["email_placeholder"])
        if st.button(t["register_btn"], use_container_width=True):
            if "@" in girilen_email and "." in girilen_email:
                basarili, mesaj = eposta_kaydet_ve_hak_ver(girilen_email.strip().lower(), secilen_dil)
                if basarili:
                    st.session_state["giris_yapilan_email"] = girilen_email.strip().lower()
                    st.success(mesaj)
                    st.rerun()
                else:
                    st.error(mesaj)
            else:
                st.warning(t["invalid_email"])
    else:
        kalan = kullanici_hak_getir(aktif_email)
        st.success(f"{t['session_active']}:\n`{aktif_email}`")
        st.metric(label=t["remaining_rights"], value=kalan)
    
    st.markdown("---")
    st.markdown(f"### {t['support_title']}")
    st.markdown(t["support_desc"])
    st.markdown(t["support_thanks"])

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
    if "Kritik port saptanmadı" not in acik_portlar[0] and "No critical port" not in acik_portlar[0]:
        skor += len(acik_portlar) * 12
    skor += ifsa_sayisi * 30
    skor += eksik_baslik_sayisi * 5
    if "Savunmasız" in rate_durum or "Vulnerable" in rate_durum:
        skor += 15
    if cors_durum not in ["Yok", "None"]:
        skor += 20
    return min(skor, 100)

# ==============================================================================
# YEREL DENETİM & SALDIRI YÜZEYİ (ASM) MOTORLARI
# ==============================================================================

def port_ve_servis_tara(url: str, dil: str) -> list:
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
    if aciklar:
        return aciklar
    else:
        return ["Kritik port saptanmadı (Filtreli)."] if dil == "Türkçe" else ["No critical ports detected (Filtered)."]

def alt_alan_adi_kesif(url: str, dil: str) -> str:
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
    if bulunanlar:
        return "\n".join(bulunanlar)
    else:
        return "Yaygın alt alan adı tespit edilemedi." if dil == "Türkçe" else "Common subdomains could not be detected."

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

def cors_ve_metot_denetle(url: str, dil: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    cors_yok = "Yok" if dil == "Türkçe" else "None"
    cors_zayif = "Güvensiz Origin İzni" if dil == "Türkçe" else "Insecure Origin Allowance"
    sonuc = {"cors_zafiyeti": cors_yok, "acik_metotlar": []}
    try:
        r = requests.get(url, headers={"Origin": "https://attacker-site.com"}, timeout=4, verify=False)
        if r.headers.get("Access-Control-Allow-Origin") in ["https://attacker-site.com", "*"]:
            sonuc["cors_zafiyeti"] = cors_zayif
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

def rate_limit_hizli_olc(url: str, dil: str) -> str:
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
    
    if dil == "Türkçe":
        return f"Aktif Eşik ({engellendi}/20 Blok)" if engellendi > 0 else "Savunmasız (0 Blok)"
    else:
        return f"Active Threshold ({engellendi}/20 Blocks)" if engellendi > 0 else "Vulnerable (0 Blocks)"

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

def html_rapor_olustur(hedef: str, markdown_metni: str, yama_metni: str, risk_skoru: int, dil: str) -> str:
    skor_baslik = "Kurumsal Risk Skoru" if dil == "Türkçe" else "Enterprise Risk Score"
    yama_baslik = "Savunma Yaması" if dil == "Türkçe" else "Defense Patch"
    rapor_baslik = "Güvenlik Raporu" if dil == "Türkçe" else "Security Report"
    
    govde = markdown.markdown(markdown_metni + f"\n\n### {skor_baslik}: {risk_skoru}/100\n" + f"\n\n### {yama_baslik}\n" + yama_metni, extensions=['tables', 'fenced_code'])
    return f"<!DOCTYPE html><html><body><h1>{rapor_baslik} - {hedef}</h1>{govde}</body></html>"

# ==============================================================================
# STREAMLIT ARAYÜZÜ
# ==============================================================================

st.title(t["title"])
st.markdown(t["subtitle"])

# Hak Kontrol Mantığı
aktif_email = st.session_state.get("giris_yapilan_email")
hak_bitti = False

if aktif_email:
    kalan = kullanici_hak_getir(aktif_email)
    if kalan <= 0:
        hak_bitti = True
        st.warning(t["no_rights_warning"])
else:
    if st.session_state["misafir_hak"] <= 0:
        hak_bitti = True
        st.warning(t["guest_exhausted_warning"])

col1, col2 = st.columns([4, 1])
with col1:
    hedef_url = st.text_input(t["target_input"], placeholder=t["target_placeholder"], disabled=hak_bitti)
with col2:
    st.write("")
    st.write("")
    tara = st.button(t["start_audit"], use_container_width=True, type="primary", disabled=hak_bitti)

if tara and hedef_url and not hak_bitti:
    if aktif_email:
        hak_dusur(aktif_email)
    else:
        st.session_state["misafir_hak"] -= 1

    bar = st.progress(0, text=t["audit_start"])
    
    bar.progress(20, text=t["step_1"])
    sublar = alt_alan_adi_kesif(hedef_url, secilen_dil)

    bar.progress(40, text=t["step_2"])
    acik_portlar = port_ve_servis_tara(hedef_url, secilen_dil)

    bar.progress(60, text=t["step_3"])
    ifsa_dosyalar = hassas_dosya_denetle(hedef_url)
    cors_sonuc = cors_ve_metot_denetle(hedef_url, secilen_dil)
    basliklar = baslik_ve_tls_denetle(hedef_url)
    rate_durum = rate_limit_hizli_olc(hedef_url, secilen_dil)

    bar.progress(80, text=t["step_4"])
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
    eksik_basliklar_str = ", ".join(basliklar.get('eksik_basliklar', [])) or ('Yok' if secilen_dil == 'Türkçe' else 'None')

    rapor = f"""{t['report_header']}
{t['target_label']} `{hedef_url}`

{t['score_label']} **{hesaplanan_skor} / 100**

{t['ports_title']}
{portlar_md}

{t['vuln_title']}
{t['vuln_file'].format(count=len(ifsa_dosyalar))}
{t['vuln_cors'].format(status=cors_sonuc.get('cors_zafiyeti'))}
{t['vuln_headers'].format(headers=eksik_basliklar_str)}
{t['vuln_rate'].format(rate=rate_durum)}

{t['subdomains_title']}
```text
{sublar}
```"""

    yama = savunma_yamasi_uret(hedef_url)
    bar.progress(100, text=t["audit_complete"])

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
        delta_val = f"{fark:+d} puan" if secilen_dil == "Türkçe" else f"{fark:+d} pts"

    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.metric(label=t["metric_score"], value=f"{skor_val} / 100", delta=delta_val, delta_color="inverse")
    with col_m2:
        st.metric(label=t["metric_file"], value=st.session_state.get("simdiki_ifsa", 0))
    with col_m3:
        st.metric(label=t["metric_header"], value=st.session_state.get("simdiki_baslik", 0))

    st.markdown("---")

    tab1, tab2, tab3, tab4 = st.tabs([t["tab_report"], t["tab_patch"], t["tab_history"], t["tab_download"]])
    
    with tab1:
        st.markdown(st.session_state["son_rapor"])

    with tab2:
        st.markdown(st.session_state["son_yama"])

    with tab3:
        st.subheader(t["history_title"])
        if onceki:
            st.info(f"{t['previous_scan_date']}: **{onceki['tarih']}**")
            col1, col2 = st.columns(2)
            with col1:
                st.write(t["previous_status"])
                st.write(f"- Risk Skoru / Score: `{onceki.get('risk_skoru', 0)} / 100`")
                st.write(f"- Portlar / Ports: `{', '.join(onceki.get('portlar', []))}`")
                st.write(f"- Hassas Dosya / Files: `{onceki.get('ifsa_sayisi', 0)}`")
            with col2:
                st.write(t["current_status"])
                st.write(f"- Risk Skoru / Score: `{st.session_state.get('simdiki_skor', 0)} / 100`")
                st.write(f"- Portlar / Ports: `{', '.join(st.session_state.get('simdiki_portlar', []))}`")
                st.write(f"- Hassas Dosya / Files: `{st.session_state.get('simdiki_ifsa', 0)}`")
            
            st.markdown("---")
            skor_fark = st.session_state.get('simdiki_skor', 0) - onceki.get('risk_skoru', 0)
            if skor_fark > 0:
                st.error(t["risk_worse"].format(fark=skor_fark))
            elif skor_fark < 0:
                st.success(t["risk_better"].format(fark=abs(skor_fark)))
            else:
                st.info(t["risk_same"])
        else:
            st.warning(t["no_history"])

    with tab4:
        html_kod = html_rapor_olustur(st.session_state["son_hedef"], st.session_state["son_rapor"], st.session_state["son_yama"], st.session_state.get("simdiki_skor", 0), secilen_dil)
        st.download_button(t["download_btn"], data=html_kod, file_name="rapor.html", mime="text/html", type="primary")