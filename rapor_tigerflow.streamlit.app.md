# Güvenlik Denetim Raporu: tigerflow.streamlit.app

**Siber Güvenlik Denetim Raporu: `tigerflow.streamlit.app`**

---

### 1. Genel Erişim ve Ağ Durumu
* **Erişilebilirlik:** Hedef sistem aktif ve yanıt vermektedir (`Ping: Başarılı`).
* **Açık Portlar:**
  * **Port 80 (HTTP):** Açık
  * **Port 443 (HTTPS):** Açık
* **SSL/TLS Sertifikası:** `Let's Encrypt` tarafından imzalanmış geçerli bir sertifika kullanılmaktadır.

---

### 2. Web Sunucusu ve HTTP Güvenlik İncelemesi
* **Sunucu Bilgisi İfşası:** Sunucu yanıtlarında `nginx/1.31.3` sürüm bilgisi açıkça paylaşılmaktadır.
* **Çerez (Cookie) Güvenliği:** `proxy-tracking-id` çerezi için `HttpOnly`, `Secure` ve `SameSite` bayrakları doğru yapılandırılmıştır.
* **HTTP Güvenlik Başlıkları:**
  * **Mevcut Başlıklar:** `X-Content-Type-Options: nosniff` (MIME-sniffing koruması aktif).
  * **Eksik Başlıklar:**
    * `Strict-Transport-Security (HSTS)`
    * `Content-Security-Policy (CSP)`
    * `X-Frame-Options`
    * `Referrer-Policy`
* **Hassas Dosya Kontrolü:** `/robots.txt` ve `/.well-known/security.txt` isteklerine statik metin yerine varsayılan SPA/Streamlit HTML istemci yanıtı dönmektedir.

---

### 3. E-Posta ve DNS Güvenlik Durumu
* **SPF Kaydı:** Bulunamadı.
* **DMARC Kaydı:** Bulunamadı.

---

### 4. Saptanan Riskler ve Çözüm Adımları

#### 🔴 High / Medium Riskler ve İyileştirme Yöntemleri

1. **Eksik `Strict-Transport-Security (HSTS)` Başlığı**
   * **Risk:** Kullanıcıların HTTP üzerinden güvensiz bağlantı kurmasına veya Man-in-the-Middle (MiTM) ve SSL Stripping saldırılarına maruz kalmasına yol açabilir.
   * **Çözüm:** Nginx konfigürasyonuna aşağıdaki başlığı ekleyin:
     ```nginx
     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
     ```

2. **Eksik `Content-Security-Policy (CSP)` Başlığı**
   * **Risk:** Uygulamanın Siteler Arası Betik Çalıştırma (XSS) veya yetkisiz veri sızdırma zararlılarına karşı savunmasız kalmasına neden olabilir.
   * **Çözüm:** Uygulama gereksinimlerine uygun, güvenilir kaynakları tanımlayan bir CSP politikası ekleyin:
     ```nginx
     add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
     ```

3. **Eksik `X-Frame-Options` Başlığı**
   * **Risk:** Sayfanın başka bir site içerisinde `<iframe>` ile yüklenebilmesine ve Tıklama Avcılığı (Clickjacking) saldırılarına açık hale gelmesine yol açar.
   * **Çözüm:** Sayfanın çerçeve içine alınmasını engellemek için başlığı aktif edin:
     ```nginx
     add_header X-Frame-Options "DENY" always; # veya "SAMEORIGIN"
     ```

4. **Eksik `Referrer-Policy` Başlığı**
   * **Risk:** Dış bağlantılara yönlendirme yapılırken URL içerisindeki hassas parametrelerin ve yönlendiren bilgisinin sızmasına sebep olabilir.
   * **Çözüm:** Referrer bilgisini kısıtlayın:
     ```nginx
     add_header Referrer-Policy "strict-origin-when-cross-origin" always;
     ```

#### 🟡 Bilgi İfşası ve E-Posta Güvenliği

5. **Sunucu Imza/Sürüm Bilgisi İfşası (`Server: nginx/1.31.3`)**
   * **Risk:** Saldırganların kullanılan Nginx sürümüne ait bilinen zafiyetleri (CVE) tespit edip hedeflemesini kolaylaştırır.
   * **Çözüm:** `nginx.conf` dosyası içerisine `server_tokens off;` parametresini ekleyerek sürüm bilgisini gizleyin.

6. **E-Posta Güvenlik Kayıtlarının Eksikliği (SPF & DMARC)**
   * **Risk:** Alan adı veya alt alan adı üzerinden yetkisiz e-posta gönderimi (email spoofing) yapılarak kullanıcıların hedeflenmesi riski bulunur.
   * **Çözüm:**
     * E-posta gönderimi yapılmıyorsa dahi spoofing önlemek adına DNS üzerine boş SPF kaydı ekleyin:
       `v=spf1 -all`
     * DMARC politikasını tanımlayın:
       `v=DMARC1; p=reject;`