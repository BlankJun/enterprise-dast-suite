# Güvenlik Dayanıklılık ve Savunma Yol Haritası: https://tigerflow.streamlit.app

# SİSTEM MİMARİSİ VE GÜVENLİK DEĞERLENDİRME RAPORU

**Hedef:** `https://tigerflow.streamlit.app`  
**Tarih:** 24 Mayıs 2024  
**Rol:** Kıdemli Savunma ve Sistem Mimarı  

---

## 1. Yönetici Özeti

Yapılan altyapı ve güvenlik denetimleri sonucunda `https://tigerflow.streamlit.app` hedefinin **Mimari Güvenlik Skoru 6.0 / 10** olarak değerlendirilmiştir.

* **Öne Çıkan Olumlu Bulgular:** TLS (HTTPS) aktif durumdadır. Çerezler (`proxy-tracking-id`) `Secure` ve `HttpOnly` bayraklarıyla doğru bir şekilde korunmaktadır. Sayfa hata durumlarında hassas sistem dökümü (stack trace) sızdırmamaktadır.
* **Kritik Kurumsal Riskler:**
  1. **HTTP Güvenlik Başlıkları Eksikliği:** `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP) ve `X-Frame-Options` gibi temel sıkılaştırma başlıkları eksiktir. Bu durum Clickjacking ve Cross-Site Scripting (XSS) risklerini artırmaktadır.
  2. **Gelişkin HTTP Metot İzinleri:** Nginx sunucusu `PUT`, `DELETE`, `PATCH` ve `OPTIONS` metotlarına `200 OK` yanıtı vermektedir. Yetkisiz veri manipülasyonu riski engellenmelidir.
  3. **Orantısız İstek Limiti (Rate Limiting):** Kısa süreli 50 eşzamanlı istekte herhangi bir hız sınırlama (HTTP 429) veya IP engelleme tetiklenmemiştir. Bu durum kaba kuvvet (brute-force) ve hafif DDoS saldırılarına karşı hassasiyet oluşturabilir.

---

## 2. Dış Saldırı Yüzeyi

Hedef alan adının bağlı olduğu üst alan adı (`streamlit.app`) üzerinde tespit edilen kritik alt sistem ve servis haritası aşağıda sunulmuştur:

| Alt Alan Adı / Servis | IP Adresi | Risk Değerlendirmesi / Mimarideki Rolü |
| :--- | :--- | :--- |
| `api.streamlit.app` | 35.201.127.49 | Uygulama Programlama Arayüzü (API Endpoints) |
| `auth.streamlit.app` | 35.201.127.49 | Kimlik Doğrulama / SSO Giriş Servisi |
| `admin.streamlit.app` | 35.201.127.49 | Yönetim Paneli (Kritik Yetkili Yüzey) |
| `panel.streamlit.app` | 35.201.127.49 | Kullanıcı / Yönetim Arayüzü |
| `portal.streamlit.app` | 35.201.127.49 | Kurumsal İstemci Portalı |
| `dev.streamlit.app` | 35.201.127.49 | Geliştirme Ortamı (Açık kalmamalı) |
| `test.streamlit.app` | 35.201.127.49 | Test / QA Arayüzü |
| `beta.streamlit.app` | 35.201.127.49 | Erken Erişim / Staging Servisi |
| `corp.streamlit.app` | 35.201.127.49 | Şirket İçi / Kurumsal Servisler |
| `vpn.streamlit.app` | 35.201.127.49 | Uzaktan Erişim / Ağ Geçidi |
| `mail.streamlit.app` | 35.201.127.49 | E-posta Sunucu Arayüzü |

---

## 3. Güvenlik ve Yapılandırma Bulguları

| Denetim Alanı | Mevcut Durum | Tespit Edilen Eksiklik / Risk | Önerilen Sıkılaştırma |
| :--- | :--- | :--- | :--- |
| **HTTP Güvenlik Başlıkları** | `X-Content-Type-Options: nosniff` aktif. | HSTS, CSP, X-Frame-Options, Referrer-Policy eksik. | HTTP yanıt başlıklarına HSTS, CSP ve Frame korumaları eklenmelidir. |
| **HTTP Metot Güvenliği** | GET/POST dışında PUT, DELETE, PATCH, OPTIONS izinli (HTTP 200). | Yetkisiz HTTP metotları kabul ediliyor. Veri bütünlüğü riski. | Sadece ihtiyaç duyulan metotlar (GET, POST) kabul edilmeli, diğerleri `405 Method Not Allowed` dönmelidir. |
| **İstek Eşiği (Rate Limit)** | 50 eşzamanlı istekte kısıtlama tetiklenmedi. | Otomatik tarama ve aşırı yük bindirme riskine açık. | Nginx / WAF üzerinde IP bazlı oran sınırlama (ör. `limit_req`) uygulanmalıdır. |
| **Çerez / Oturum Güvenliği** | `proxy-tracking-id` çerezi `Secure` ve `HttpOnly`. | Uygulama düzeyinde ek çerez nitelikleri kontrol edilmeli. | `SameSite=Strict` veya `Lax` parametresi eklenmelidir. |
| **E-Posta DNS Güvenliği** | `streamlit.app` kök domain yapısı. | Kurumsal phishing ve domain spoofing riski. | DNS paneli üzerinden SPF, DKIM ve DMARC (`p=reject`) kayıtları doğrulanmalıdır. |

---

## 4. Rol Bazlı Savunma Yol Haritası

### A. DevOps / Sistem Yöneticisi (Altyapı ve Kural Blokları)
1. **Nginx Başlık Sıkılaştırması:**  
   `nginx.conf` veya ters proxy yapılandırmanıza aşağıdaki kuralları ekleyin:
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
   add_header X-Frame-Options "DENY" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
   ```
2. **Kabul Edilmeyen HTTP Metotlarının Engellenmesi:**
   ```nginx
   if ($request_method !~ ^(GET|POST|HEAD)$ ) {
       return 405;
   }
   ```
3. **Rate Limiting Uygulanması:**
   ```nginx
   limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
   limit_req zone=one burst=20 nodelay;
   ```

### B. Yazılım Geliştirici (Uygulama Seviyesi Sıkılaştırma)
1. **Çerez Konfigürasyonu:** Tüm çerezlere `SameSite=Lax` veya `SameSite=Strict` özniteliğini ekleyin.
2. **Girdi ve Çıktı Doğrulama:** İçerik Güvenlik Politikası (CSP) kısıtlamalarına paralel olarak kullanıcıdan alınan tüm verileri sanitize edin (XSS önlemleri).
3. **Hata Yönetimi:** Production ortamında detaylı sistem mesajlarının kapalı tutulduğunu (`404` ve `500` custom hata sayfaları) doğrulamaya devam edin.

### C. Ürün Sahibi (İş Sürekliliği ve Risk Yönetimi)
1. **E-posta Kimlik Doğrulama Politikaları:** Kurumsal alan adından gönderilen e-postaların taklit edilmesini önlemek adına DMARC `p=reject` politikasına geçilmesini sağlayın.
2. **Dış Varlık ve Alt Alan Adı Envanteri:** `dev`, `test`, `admin` gibi dışa açık alt alan adlarını ip kısıtlaması (IP Whitelisting) veya VPN arkasına taşıyarak korumaya alın.
3. **Düzenli Sızma Testleri:** Yılda en az iki kez bağımsız üçüncü taraf sızma testleri ile sistem dayanıklılığını ölçümleyin.


================================================================================
🛠️ OTOMATİK SAVUNMA VE YAMA KODLARI (AUTO-PATCH)
Hedef: tigerflow.streamlit.app
================================================================================

[1] NGINX YAPILANDIRMASI (/etc/nginx/sites-available/tigerflow.streamlit.app)
--------------------------------------------------------------------------------
limit_req_zone $binary_remote_addr zone=tigerflow_streamlit_app_limit:10m rate=15r/s;

server {
    server_name tigerflow.streamlit.app;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none';" always;

    # Tehlikeli HTTP Metotlarini Yasakla
    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
        return 405;
    }

    location / {
        limit_req zone=tigerflow_streamlit_app_limit burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8501;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

[2] CLOUDFLARE WAF / TRANSFORM KURALLARI
--------------------------------------------------------------------------------
* HTTP Metot Filtresi:
  Rule Expression : (http.request.method in {"PUT" "DELETE" "TRACE"})
  Action          : Block (HTTP 405)

* Rate Limiting Kuralı:
  Traffic matching: (http.host eq "tigerflow.streamlit.app")
  Rate            : IP basina 60 saniyede 30 istek
  Action          : Block (HTTP 429)

* SSL/TLS Ayarı:
  SSL/TLS -> Edge Certificates -> "Always Use HTTPS" = ON
  SSL/TLS -> Edge Certificates -> "HSTS" = Enable (Max Age: 12 months)
================================================================================
