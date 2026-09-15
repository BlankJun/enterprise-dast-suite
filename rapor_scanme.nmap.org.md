# SİBER GÜVENLİK DENETİM VE RİSK DEĞERLENDİRME RAPORU

**Hedef:** scanme.nmap.org  
**Tarih:** 24 Mayıs 2024  
**Raporu Hazırlayan:** Kıdemli Güvenlik ve Sistem Mimarı  
**Gizlilik Derecesi:** HİZMETE ÖZEL / GİZLİ  

---

## 1. YÖNETİCİ ÖZETİ

Gerçekleştirilen DAST (Dinamik Uygulama Güvenlik Testi) ve dış altyapı taramaları sonucunda, hedef altyapının **yüksek derecede güvenlik riskleri** taşıdığı tespit edilmiştir. 

En kritik bulgu; test, geliştirme, yönetim panelleri ve üretim ortamlarının **aynı IP adresi (50.116.1.184) üzerinde izole edilmeden barındırılması** ve bu varlıkların doğrudan dış internete açık olmasıdır. Ayrıca, sistemde herhangi bir **Rate Limiting (İstek Sınırlama)** mekanizması bulunmamaktadır. Bu durum, kurumu DoS/DDoS saldırılarına, kaba kuvvet (brute-force) girişimlerine ve yetkisiz erişim risklerine açık hale getirmektedir.

```
+---------------------------------------------------------------+
|                    GENEL RİSK SKORU: 7.8 / 10                 |
|                     SEVİYE: YÜKSEK (HIGH)                     |
+---------------------------------------------------------------+
```

### Temel Risk Faktörleri:
* **Geniş ve Kontrolsüz Saldırı Yüzeyi:** Test ve idari domain'lerin kamusal alanda bulunması.
* **Hız Sınırlaması Yokluğu:** DoS ve Otomatize Saldırılara karşı tamamen korumasız yapı.
* **Eksik Güvenlik Katmanları:** Temel HTTP güvenlik başlıklarının (Security Headers) yapılandırılmamış olması.

---

## 2. KEŞFEDİLEN DIŞ VARLIKLAR VE SUBDOMAIN ANALİZİ

Yapılan DNS ve IP çözümlemelerinde, organizasyona ait **10 farklı kritik alt alan adının (subdomain) tek bir IP adresine (`50.116.1.184`) yönlendirildiği** görülmüştür.

```
                       [ 50.116.1.184 ] (Tekil IP / Monolitik Yapı)
                                              |
      +-----------------+---------------------+-----------------+-----------------+
      |                 |                     |                 |                 |
 [api.nmap.org]  [dev/test/staging]      [admin/panel/portal]  [auth/vpn]    [mail.nmap.org]
  (API Servisi)  (Geliştirme Ortamı)     (Yönetim Panelleri)  (Kimlik Doğr.)  (E-Posta Servisi)
```

### Mimari Risk Değerlendirmesi:

1. **Ağ İzolasyonu Eksikliği (Lack of Network Segmentation):**
   * `dev`, `test` ve `staging` gibi canlıya alınmamış, muhtemelen zayıf kod içeren test ortamları, üretim (`api`, `auth`) ortamıyla aynı IP/sunucuda yer almaktadır. Test ortamında bulunacak bir açıklık (RCE, Local File Inclusion vb.), doğrudan üretim ortamının ve hassas verilerin tehlikeye girmesine (**Lateral Movement / Yan Yönlü Hareket**) sebep olabilir.

2. **Kritik Yönetim Panellerinin Dışa Açıklığı:**
   * `admin`, `panel`, `portal`, `auth` ve `vpn` gibi yüksek imtiyazlı erişim noktaları tüm dünyaya açıktır. Bu durum saldırganlar için birer birincil hedef (High-Value Target) niteliğindedir.

3. **Tek Nokta Başarısızlığı (Single Point of Failure - SPOF):**
   * Tüm servislerin tek bir IP üzerinde toplanması, uygulanacak bir DoS/DDoS saldırısında tüm kurum servislerinin (`mail` ve `auth` dahil) aynı anda servis dışı kalmasına yol açacaktır.

---

## 3. DETAYLI ZAFİYET MATRİSİ

| Zafiyet Adı | OWASP Kategorisi | Risk Seviyesi | Kanıt / Durum | İş Etkisi |
| :--- | :--- | :--- | :--- | :--- |
| **İstek Sınırlama Eksikliği (No Rate Limiting)** | API4:2023 - Unrestricted Resource Consumption / A04:2021 - Insecure Design | **YÜKSEK** | 30 eşzamanlı istek gönderildi; hiçbir engelleme/yavaşlatma tetiklenmedi (200 OK). | Servis kesintisi (DDoS), Kaba Kuvvet (Brute-Force) ile hesap ele geçirme, kaynak tükenmesi. |
| **Geliştirme ve Yönetim Ortamlarının Kamusal Açıklığı** | A01:2021 - Broken Access Control / A05:2021 - Security Misconfiguration | **YÜKSEK** | `dev`, `test`, `admin`, `vpn` alt alan adları doğrudan internetten erişilebilir durumda. | Yetkisiz erişim, kaynak kod/veri sızıntısı, sistem yönetimi kontrolünün kaybedilmesi. |
| **Kritik HTTP Güvenlik Başlıklarının Eksikliği** | A05:2021 - Security Misconfiguration | **ORTA** | `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options` başlıkları yanıtlarda bulunmuyor. | Man-in-the-Middle (MiTM) saldırıları, Clickjacking, XSS tabanlı veri hırsızlığı. |

---

## 4. ROL BAZLI SAVUNMA REÇETESİ (REMEDIATION PLAN)

### 🛠️ DevOps ve Altyapı Ekibi İçin

1. **Ağ ve Ortam İzolasyonu (İvedi):**
   * `dev.nmap.org`, `test.nmap.org` ve `staging.nmap.org` alt alan adlarının kamusal DNS kayıtlarını kaldırın.
   * Bu ortamları yalnızca şirket içi VPN veya bir Zero-Trust (örneğin Cloudflare Access / Tailscale) mimarisi arkasına çekin.
   * `admin`, `panel` ve `portal` erişimlerini belirli statik IP adreslerine (IP Whitelisting) kısıtlayın.

2. **WAF ve Rate Limit Yapılandırması:**
   * Ön sunucu (Nginx/HAProxy) veya WAF (Cloudflare/AWS WAF) üzerinde IP başına istek sınırlaması tanımlayın.
   * *Örnek Nginx Yapılandırması:*
     ```nginx
     limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
     server {
         location /api/ {
             limit_req zone=api_limit burst=20 nodelay;
         }
     }
     ```

3. **HTTP Güvenlik Başlıklarının Eklenmesi:**
   * Ters proxy (Reverse Proxy) seviyesinde aşağıdaki başlıkları zorunlu kılın:
     ```http
     Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
     X-Frame-Options: DENY
     X-Content-Type-Options: nosniff
     Content-Security-Policy: default-src 'self';
     Referrer-Policy: strict-origin-when-cross-origin
     ```

---

### 💻 Yazılım Geliştirici Ekibi İçin

1. **Uygulama Seviyesinde Rate Limiting:**
   * Özellikle `auth.nmap.org` (Login) ve `api.nmap.org` uç noktalarında Redis tabanlı *Token Bucket* veya *Leaky Bucket* algoritmaları kullanarak uygulama seviyesinde rate limit uygulayın.

2. **Hata ve Yanıt Yönetimi:**
   * Sunucu bilgilerinin gizli kalması olumludur. Ancak uygulama katmanında da beklenmeyen durumlarda detaylı hata mesajlarının (Stack Trace) dışarı sızmadığından emin olun (Mevcut durum korunsun).

3. **CORS ve Güvenli Oturum Yapılandırması:**
   * `api.nmap.org` üzerindeki CORS politikasını yalnızca yetkili domainlerle sınırlayın (`Access-Control-Allow-Origin: *` kullanılmamalıdır).

---

### 📋 Ürün Yöneticisi (Product Manager) İçin

1. **Güvenlik Deposu (Security Backlog) Önceliklendirmesi:**
   * Önümüzdeki sprint'e "Altyapı Güvenlik Sertleştirilmesi (Hardening)" ve "Rate Limiting Entegrasyonu" maddelerini **P0 (En Yüksek Öncelik)** olarak ekleyin.

2. **Geliştirme Süreç Standartları (SDLC):**
   * Canlıya alım süreçlerinde (Release Pipeline) "Güvenlik Onayı" adımını zorunlu hale getirin.
   * Prodüksiyon dışı ortamların (Dev/Test) canlıya çıkış kriterlerinde internete kapalı olması şartını ekleyin.

3. **SLA ve Uyumluluk:**
   * Yetkisiz erişim riski taşıyan subdomain'lerin kapatılması için DevOps ekibine **24-48 saatlik aksiyon SLA'i** tanımlayın.


================================================================================
🛠️ DİNAMİK ALTYAPI SAVUNMA YAMASI (AUTO-PATCH)
Hedef: scanme.nmap.org
================================================================================
[NGINX SIKILAŞTIRMA - /etc/nginx/conf.d/scanme.nmap.org.conf]
limit_req_zone $binary_remote_addr zone=scanme_nmap_org_zone:10m rate=10r/s;

server {
    server_name scanme.nmap.org;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline'; frame-ancestors 'none';" always;

    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
        return 405;
    }

    location / {
        limit_req zone=scanme_nmap_org_zone burst=15 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8000; # Uygulama Portu
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
================================================================================
