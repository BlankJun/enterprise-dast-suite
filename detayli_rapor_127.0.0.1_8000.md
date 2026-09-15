# Kapsamlı Güvenlik ve Rota Denetim Raporu: 127.0.0.1:8000

# Güvenlik ve Dayanıklılık Denetim Raporu

**Hedef:** `http://127.0.0.1:8000`  
**Tarih:** 24 Mayıs 2024  
**Denetim Tipi:** Web Güvenlik, Rota Keşfi ve Dayanıklılık (Rate-Limit) Analizi  
**Denetçi Profili:** Savunma Odaklı Kıdemli Web Güvenlik ve Dayanıklılık Denetim Uzmanı  

---

## 1. Yönetici Özeti

Yapılan güvenlik ve dayanıklılık analizi sonucunda, **127.0.0.1:8000** adresinde çalışan servisin geliştirme amacıyla kullanılan varsayılan Python HTTP sunucusu (`SimpleHTTP/0.6 Python/3.13.1`) olduğu tespit edilmiştir. 

Servis üzerinde yapılan analizlerde **yüksek riskli kaynak kod ve hassas rapor dosyası ifşası**, **eksik HTTP güvenlik başlıkları**, **rate-limiting (hız sınırlaması) eksikliği** ve **HTTPS şifrelemesinin bulunmaması** gibi temel güvenlik eksiklikleri saptanmıştır. Bu servisin üretim (production) ortamına taşınmadan önce prodüksiyon seviyesinde bir web sunucusu/ters proxy (Nginx, Caddy, Gunicorn vb.) arkasına alınması ve sertleştirme adımlarının uygulanması kritik önem taşımaktadır.

---

## 2. Sistem ve Tarama Özet Tablosu

| Metrik / Kontrol | Durum / Değer | Risk Derecesi |
| :--- | :--- | :--- |
| **Ağ Erişilebilirliği (Ping)** | Erişilebilir (`127.0.0.1`) | Bilgi |
| **Açık Port** | `8000/TCP` Açık | Bilgi |
| **Web Sunucusu** | `SimpleHTTP/0.6 Python/3.13.1` | **YÜKSEK** |
| **Dizin İfşası / Kaynak Kod İfşası** | Hassas dosyalar ve Python kodları açıkta | **KRİTİK** |
| **HTTP Güvenlik Başlıkları** | Tümü Eksik (CSP, HSTS, XFO, XCTO vb.) | **ORTA** |
| **Hız Sınırlaması (Rate-Limit)** | Yok (60+ istek engellenmedi) | **ORTA** |
| **SSL/TLS (HTTPS)** | Devre Dışı (Düz Metin HTTP) | **DÜŞÜK** (Yerel test için) |
| **Hassas Dosyalar (robots.txt/security.txt)** | Bulunamadı (404) | **DÜŞÜK** |

---

## 3. Web Rota Keşfi ve Varlık Haritası

Yapılan crawler (web rota keşfi) çalışmasında sunucu kök dizinindeki tüm dosya ve dizin yapısı haritalandırılmıştır. Varsayılan `SimpleHTTP` modülü dizin listelemeyi (Directory Listing) engellemediği veya dosyaları doğrudan sunduğu için aşağıdaki hassas varlıklar tespit edilmiştir:

```
http://127.0.0.1:8000/
├── audit_agent.py                          [Kaynak Kod Dosyası]
├── detayli_rapor_127.0.0.1_8000.md         [Güvenlik Raporu / İç Bilgi]
├── detayli_rapor_pip install beautifulsoup4.md
├── detayli_rapor_tigerflow.streamlit.app.md
├── rapor_127.0.0.1_8000.md
├── rapor_python audit_agent.py.md
└── rapor_tigerflow.streamlit.app.md
```

### Risk Analizi: Kaynak Kod ve Rapor İfşası
* **Etki:** `audit_agent.py` dosyasının doğrudan indirilip incelenebilmesi, uygulamanın mantıksal zafiyetlerinin, dahili kütüphanelerinin ve olası yetkilendirme mekanizmalarının saldırganlarca analiz edilmesine (White-box yetkisiz erişim) imkan tanır.
* **Markdown Raporları:** Daha önce yürütülen güvenlik denetimi sonuçları ve sistem detayları yetkisiz kişilerin erişimine açıktır.

---

## 4. Ayrıntılı Bulgular ve Risk Değerlendirmesi

### B-01: Üretim Ortamında Geliştirme Sunucusu Kullanımı ve Kaynak Kod İfşası
* **Risk Derecesi:** **KRİTİK**
* **Açıklama:** Sunucu yanıt başlıklarında `Server: SimpleHTTP/0.6 Python/3.13.1` tespit edilmiştir. Python'un varsayılan `http.server` modülü güvenlik, performans ve erişim kontrolü için tasarlanmamıştır. Dizin içeriklerini doğrudan dışarıya sunmaktadır.
* **Tehdit Senaryosu:** Saldırgan, `/audit_agent.py` dosyasını indirerek uygulama mimarisini inceleyebilir, dosya sistemindeki statik belgeleri okuyabilir.

### B-02: Rate Limit (Hız Sınırı) Korumasının Bulunmaması
* **Risk Derecesi:** **ORTA / YÜKSEK**
* **Açıklama:** Yapılan testlerde kısa sürede gönderilen 60 eşzamanlı isteğin tamamı `200 OK` yanıtı almış, `429 Too Many Requests` veya `403 Forbidden` engelleyici mekanizması devreye girmemiştir.
* **Tehdit Senaryosu:** Uygulama, Hizmet Engelleme (DoS/DDoS) saldırılarına, dizin ve dosya kaba kuvvet (brute-force) taramalarına karşı açık durumdadır.

### B-03: Eksik HTTP Güvenlik Başlıkları
* **Risk Derecesi:** **ORTA**
* **Açıklama:** Uygulama yanıtlarında aşağıdaki temel güvenlik başlıklarının hiçbiri yer almamaktadır:
  * `Content-Security-Policy (CSP)`: XSS ve kod enjeksiyonu koruması.
  * `X-Frame-Options`: Clickjacking (Tıklama Avcılığı) koruması.
  * `X-Content-Type-Options`: MIME-sniffing koruması (`nosniff`).
  * `Strict-Transport-Security (HSTS)`: HTTPS zorunluluğu.
  * `Referrer-Policy`: Hassas URL bilgilerinin dışarı sızmasını önleme.
  * `Permissions-Policy`: Tarayıcı özelliklerine erişim kısıtlaması.

---

## 5. Doğrudan Uygulanabilir Sertleştirme ve Koruma Kodları

### 1. Nginx Ters Proxy (Reverse Proxy) ve Rate-Limiting Yapılandırması
Geliştirme sunucusunu doğrudan dışarıya açmak yerine, önüne Nginx ekleyerek güvenlik başlıkları ve hız sınırlaması uygulanmalıdır.

`/etc/nginx/sites-available/default` veya `/etc/nginx/conf.d/security.conf`:

```nginx
# Rate limiting bölgesi tanımlama (Saniye başına 10 istek, IP bazlı)
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    listen 80;
    server_name 127.0.0.1 localhost;

    # Güvenlik Başlıkları (Security Headers)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Sunucu Versiyon Bilgisini Gizleme
    server_tokens off;

    location / {
        # Rate limit uygulama (Burst toleransı: 20)
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Kaynak kodlarının (.py) ve Markdown (.md) raporlarının engellenmesi
    location ~* \.(py|pyc|md|log|env|git)$ {
        deny all;
        return 404;
    }
}
```

---

### 2. Python FastAPI / WSGI Prodüksiyon Sunucusu Örneği (Uvicorn/Gunicorn + SlowAPI)

Eğer uygulama Python tabanlı özel bir servis ise, `SimpleHTTP` yerine `Gunicorn`/`FastAPI` ve `slowapi` ile hız sınırlaması eklenmelidir:

```python
from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Güvenlik Başlıkları Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

@app.get("/")
@limiter.limit("10/minute") # Dakikada maksimum 10 istek
async def root(request: Request):
    return {"status": "Guvendeler", "message": "Servis aktif ve korumali."}
```

---

## 6. Sonuç ve Önerilen Yol Haritası

1. **Acil Eylem:** `http.server` (SimpleHTTP) servisi derhal kapatılmalı veya hassas `.py` / `.md` dosyalarının bulunduğu dizinden başka boş/statik bir dizine taşınmalıdır.
2. **Mimari Güncelleme:** Prodüksiyon için Gunicorn/Uvicorn veya Nginx / Caddy ters proxy mimarisine geçilmelidir.
3. **Güvenlik Başlıkları:** Nginx veya uygulama seviyesinde `X-Frame-Options`, `X-Content-Type-Options` ve `CSP` aktif edilmelidir.
4. **Rate Limit:** IP başına saniyelik/dakikalık istek sınırlaması getirilmelidir.
5. **Bilgilendirme Dosyaları:** Standardizasyon için `robots.txt` ve `/.well-known/security.txt` dosyaları oluşturulmalıdır.