# Derinlemesine Güvenlik ve Mimari Denetim Raporu: tigerflow.streamlit.app

# `tigerflow.streamlit.app` Güvenlik ve Mimari Denetim Raporu

---

## 1. Yönetici Özeti & Mimari Profil

Yapılan otomatize DAST (Dinamik Uygulama Güvenlik Testi) ve parmak izi analizleri sonucunda hedef uygulamanın mimari bileşenleri ve genel güvenlik durumu aşağıdaki gibidir:

* **Çalışma Zamanı (Framework):** Streamlit (Python Veri & Web Uygulaması)
* **Ters Vekil / Web Sunucu (Reverse Proxy):** Nginx / 1.31.3
* **SSL/TLS Sertifikası:** Let's Encrypt (Geçerli - Kalan Gün: ~56)
* **Açık Portlar:** 443 (HTTPS)
* **Genel Risk Skoru:** **6/10 (Orta Seviye Risk)**

### Özet Değerlendirme
Uygulama temel seviyede gizlilik sağlasa da (çerez politikaları uygun, teknik hata sızıntısı yok), HTTP güvenlik başlıklarının büyük çoğunluğunun eksik olması, PUT/DELETE gibi tehlikeli HTTP metotlarının işlenmesi ve herhangi bir **Rate-Limiting (Hız Sınırlama)** mekanizmasının bulunmaması nedeniyle DoS risklerine ve Cross-Site Scripting (XSS) / Clickjacking gibi istemci tarafı saldırılara açıktır.

---

## 2. Detaylı Zafiyet Matrisi

| Zafiyet Adı | OWASP Kategorisi | Risk Düzeyi | Kanıt (Evidence) |
| :--- | :--- | :--- | :--- |
| **Eksik HTTP Güvenlik Başlıkları** | **A05:2021 – Security Misconfiguration** | **Orta** | `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `Referrer-Policy` ve `Permissions-Policy` başlıkları HTTP yanıtlarında bulunmuyor. Yalnızca `X-Content-Type-Options: nosniff` tespit edildi. |
| **Gelişmiş HTTP Metotlarının Açık Olması** | **A05:2021 – Security Misconfiguration** | **Orta** | `OPTIONS`, `PUT`, `DELETE` metotlarına sunucu tarafından `200 OK` yanıtı dönülmektedir. |
| **Hız Sınırlaması (Rate Limit) Eksikliği** | **A04:2021 – Insecure Design** | **Yüksek** | 60 eşzamanlı istek testinde hiçbir istek engellenmemiş (`429 Too Many Requests` veya `403 Forbidden` alınmamıştır). |

---

## 3. Hız Sınırı (Rate-Limiting) & Dayanıklılık Analizi

Uygulama üzerinde kademeli eşzamanlı istek yükleme testi gerçekleştirilmiştir:

* **5 Eşzamanlı İstek:** %100 Başarılı (0 Engel)
* **15 Eşzamanlı İstek:** %100 Başarılı (0 Engel)
* **30 Eşzamanlı İstek:** %100 Başarılı (0 Engel)
* **60 Eşzamanlı İstek:** %100 Başarılı (0 Engel)

**Sonuç:** Sunucu önünde aktif bir Web Application Firewall (WAF) veya Nginx seviyesinde `limit_req` kuralı bulunmamaktadır. Otomatize botlar ve kaynak tükenme saldırılarına (Resource Exhaustion DoS) karşı savunmasızdır.

---

## 4. Hedefe ve Teknolojiye Özel Çözüm Kodları

### A. Streamlit Yapılandırması (`.streamlit/config.toml`)
Streamlit uygulamasının güvenlik ayarlarını sıkılaştırmak için proje kök dizinindeki yapılandırma dosyasına şu parametreleri ekleyin:

```toml
[server]
# CORS güvenlik denetimini etkinleştirin
enableCORS = true

# XSRF / CSRF korumasını etkinleştirin
enableXsrfProtection = true

# WebSocket ve dosya yükleme sınırlarını belirleyin
maxUploadSize = 200

[browser]
# Uygulamanın iframe içerisinde çağrılmasını engellemek için
gatherUsageStats = false
```

---

### B. Nginx Web Sunucusu Yapılandırması (`nginx.conf`)
Ön katmanda çalışan Nginx ters vekil sunucusuna eksik HTTP başlıklarını eklemek, gereksiz HTTP metotlarını engellemek ve Rate-Limiting tanımlamak için aşağıdaki bloğu uygulayın:

```nginx
# Rate limiting bölgesi tanımlama (Saniyede 10 istek limiti)
limit_req_zone $binary_remote_addr zone=streamlit_limit:10m rate=10r/s;

server {
    listen 443 ssl http2;
    server_name tigerflow.streamlit.app;

    # SSL Sıkılaştırma (HSTS)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Güvenlik Başlıkları
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none';" always;

    # İzin verilmeyen HTTP metotlarını engelleme
    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
        return 405;
    }

    location / {
        # Rate Limiting Uygulama
        limit_req zone=streamlit_limit burst=20 nodelay;
        limit_req_status 429;

        proxy_pass http://127.0.0.1:8501; # Streamlit varsayılan portu
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```