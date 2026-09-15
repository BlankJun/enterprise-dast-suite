# Kapsamlı Güvenlik ve Rota Denetim Raporu: tigerflow.streamlit.app

# Web Güvenlik ve Dayanıklılık Denetim Raporu

**Hedef:** `tigerflow.streamlit.app`  
**Tarih:** 16 Eylül 2026  
**Denetim Tipi:** Dış Ağ, Web Uygulaması ve Dayanıklılık (Rate-Limit) Denetimi  
**Uzmanlık Rolü:** Savunma Odaklı Kıdemli Web Güvenlik ve Dayanıklılık Uzmanı  

---

## 1. Yönetici Özeti (Executive Summary)

`tigerflow.streamlit.app` alan adı üzerinde gerçekleştirilen güvenlik denetimi; SSL/TLS sertifika yapısı, HTTP güvenlik yanıt başlıkları, çerez konfigürasyonları, statik hassas dosya uçları, web rota mimarisi ve yük/hız sınırı (Rate Limit) dayanıklılığını kapsayan çok katmanlı bir analizle tamamlanmıştır.

Yapılan testler sonucunda uygulamanın **Let's Encrypt** tabanlı geçerli bir SSL sertifikasına sahip olduğu ve kullanılan tracking çerezlerinin (`proxy-tracking-id`) güvenlik bayraklarının (`Secure`, `HttpOnly`, `SameSite`) eksiksiz tanımlandığı tespit edilmiştir. Ancak, uygulamanın önünde konumlanan web sunucusunda (Nginx/1.31.3) kritik güvenlik başlıklarının eksik olduğu, statik dosya isteklerinin (örn. `robots.txt`, `security.txt`) varsayılan HTML Single Page Application (SPA) katmanına yönlendiği ve istemci bazlı hız sınırı (rate-limiting) mekanizmasının yetersiz kaldığı gözlemlenmiştir.

---

## 2. Bulgular ve Risk Derecelendirmesi Özet Tablosu

| Bilesen / Kontrol | Durum | Risk Seviyesi | Açıklama |
| :--- | :--- | :--- | :--- |
| **SSL / TLS Sertifikası** |  Başarılı | **Düşük (Informational)** | Let's Encrypt sertifikası geçerli, kalan süre yeterli (~56 gün). |
| **Ağ Port Açıklığı** |  Açık | **Düşük** | HTTP (80) ve HTTPS (443) portları açık ve hizmet veriyor. |
| **Çerez (Cookie) Güvenliği** |  Başarılı | **Düşük (Informational)** | `proxy-tracking-id` çerezi tam korumalı. |
| **HTTP Güvenlik Başlıkları** |  Kısmi | **Orta (Medium)** | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy eksik. |
| **Hız Sınırı (Rate Limiting)** |  Eksik | **Yüksek (High)** | 60 eşzamanlı/ardışık istekte kısıtlama (429/403) uygulanmadı. |
| **Hassas Dosya Kontrolü** |  Yapılandırma Hatası | **Düşük (Low)** | `robots.txt` ve `security.txt` dinamik SPA HTML çıktısı dönüyor. |

---

## 3. Detaylı Güvenlik Bulguları ve Analiz

### 3.1. SSL/TLS ve Ağ Analizi
- **Sertifika Sağlayıcı:** Let's Encrypt
- **Geçerlilik Durumu:** Aktif (~56 gün kalan süre)
- **Aşırı Port Taraması:** 80 (HTTP) ve 443 (HTTPS) TCP portları erişilebilir durumdadır.
- **Değerlendirme:** SSL sertifikası güncel ve güvenilirdir. HTTP -> HTTPS yönlendirmesinin ve HSTS başlığının zorunlu kılınması altyapı güvenliğini pekiştirecektir.

### 3.2. HTTP Güvenlik Başlıkları ve Sunucu Yapılandırması
Sunucu `nginx/1.31.3` versiyon bilgisi yaymaktadır. Alınan yanıt başlığı analizi aşağıdaki gibidir:

- **X-Content-Type-Options:** `nosniff` (Mevcut )
- **Strict-Transport-Security (HSTS):** Eksik 
  - *Risk:* HTTPS üzerinden veri iletimini zorunlu kılmadığından Man-in-the-Middle (MitM) ve Downgrade saldırılarına karşı açık oluşturabilir.
- **Content-Security-Policy (CSP):** Eksik 
  - *Risk:* XSS (Cross-Site Scripting) ve veri sızdırma senaryolarına karşı tarayıcı düzeyinde koruma kalkanı eksiktir.
- **X-Frame-Options:** Eksik 
  - *Risk:* Uygulamanın iframe içerisine gömülmesine izin vererek Clickjacking saldırılarına zemin hazırlar.
- **Referrer-Policy:** Eksik 
  - *Risk:* Dış bağlantılara gidilirken hassas URL parametrelerinin ve oturum verilerinin sızmasına yol açabilir.
- **Permissions-Policy:** Eksik 
  - *Risk:* Tarayıcı donanım erişimlerinin (kamera, mikrofon, konum) kısıtlanmamasına neden olur.

### 3.3. Çerez (Cookie) Güvenliği
- **İncelenen Çerez:** `proxy-tracking-id`
- **Analiz Sonucu:** `Secure`, `HttpOnly` ve `SameSite` parametreleri tam ve doğru şekilde tanımlanmıştır. İstemci tarafında çalışan zararlı JavaScript kodlarının çerez verisini okuması engellenmiştir.

### 3.4. Rota Keşfi ve Hassas Dosya Analizi
- **Rota Yapısı:** `https://tigerflow.streamlit.app` ana dizini üzerinden Streamlit SPA (Single Page Application) mimarisinde hizmet vermektedir.
- **Dizin/Dosya Analizi:** `/robots.txt` ve `/.well-known/security.txt` gibi standart uç noktalara yapılan isteklerde sunucu varsayılan istemci HTML kodunu (`<!doctype html>...`) döndürmektedir.
- **Değerlendirme:** SPA yönlendirme (Fallback) mekanizması, var olmayan dosyalar için 404 dönmek yerine 200 OK yanıtı ile ana uygulamayı yüklemektedir. Bu durum arama motoru taranabilirliği ve güvenlik muhatabı tespiti açısından düzeltilmelidir.

### 3.5. Dayanıklılık ve Hız Sınırı (Rate-Limiting) Analizi
- **Gerçekleştirilen Test:** Kademeli istek artışı (5, 15, 30 ve 60 eşzamanlı istek).
- **Sonuç:** 60 isteğe kadar hiçbir istek `429 Too Many Requests` veya `403 Forbidden` engeline takılmamış, tümü `200 OK` yanıtı almıştır.
- **Risk:** Saldırganların otomatik botlar, kaba kuvvet (brute-force) veya kaynak tüketme (DoS - Denial of Service) yöntemleriyle uygulamayı servis dışı bırakma riskini artırmaktadır.

---

## 4. İyileştirme ve Sertleştirme Önerileri (Remediation & Hardening)

### 4.1. Nginx Güvenlik Başlıkları ve Hız Sınırı Yapılandırması (`nginx.conf`)
Streamlit uygulamasının önünde yer alan Nginx ters proxy (reverse proxy) katmanına aşağıdaki konfigürasyon eklenmelidir:

```nginx
# Rate Limit Tanımlaması (IP Başına Saniyede 10 İstek, 10M Bellek Alanı)
limit_req_zone $binary_remote_addr zone=streamlit_limit:10m rate=10r/s;

server {
    listen 443 ssl http2;
    server_name tigerflow.streamlit.app;

    # SSL Sertifika Tarafı
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # HTTP Güvenlik Başlıkları Sertleştirme
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Streamlit Websocket ve Statik Kaynaklar için CSP
    add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss: https:;" always;

    # Sunucu İmzasını Gizleme
    server_tokens off;

    # Hız Sınırı (Rate Limiting) Uygulaması
    location / {
        limit_req zone=streamlit_limit burst=20 nodelay;
        limit_req_status 429;

        proxy_pass http://127.0.0.1:8501; # Streamlit Portu
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Gerçek Statik Dosya / robots.txt İstisnaları
    location = /robots.txt {
        add_header Content-Type text/plain;
        return 200 "User-agent: *\nDisallow: /\n";
    }

    location = /.well-known/security.txt {
        add_header Content-Type text/plain;
        return 200 "Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z\n";
    }
}
```

### 4.2. Streamlit Uygulama Katmanı Sertleştirmesi (`.streamlit/config.toml`)
Streamlit uygulamasının kök dizininde bulunan `.streamlit/config.toml` dosyası güncellenmelidir:

```toml
[server]
headless = true
enableCORS = false
enableXsrfProtection = true
maxUploadSize = 200

[browser]
gatherUsageStats = false
```

### 4.3. Cloudflare / WAF Düzeyinde Hız Sınırı (Rate Limiting) Kuralı
Eğer uygulama Cloudflare veya benzer bir WAF arkasında sunuluyorsa, WAF üzerinde şu kural oluşturulmalıdır:

- **Eylem (Action):** Block / Managed Challenge / Rate Limit
- **Koşul:** `(http.request.uri.path contains "/")`
- **Eşik Değer (Threshold):** 10 saniye içinde IP başına 30 istekten fazla gelirse `429 Too Many Requests` döndür.

---

## 5. Sonuç ve İş Planı

1. **Öncelikli Adım:** Nginx/Proxy katmanında `HSTS`, `X-Frame-Options` ve `Content-Security-Policy` başlıklarının devreye alınması.
2. **İkinci Adım:** Otomatik tarama ve DoS risklerini engellemek için IP tabanlı Rate-Limit eşiklerinin (ör. 10 req/sec) yapılandırılması.
3. **Üçüncü Adım:** `robots.txt` ve `security.txt` dosyalarının düzgün içerik verecek şekilde yönlendirme kurallarının güncellenmesi.