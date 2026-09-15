# Güvenlik Denetim Raporu: python audit_agent.py

**Belirtilen Hedef Hakkında Değerlendirme:**

`python audit_agent.py` bir web sitesi, etki alanı (domain) veya IP adresi olmayıp, yerel bir **Python komutu/betik adı**dır. Ağ/web seviyesinde çalışan uzaktan denetim araçları (Ping, Port Taraması, SSL, HTTP Güvenlik Başlıkları, SPF/DMARC denetimleri) yalnızca erişilebilir bir alan adı veya IP adresi üzerinde çalıştırılabilir.

Ancak savunma odaklı kıdemli bir güvenlik uzmanı perspektifiyle, **bir Güvenlik Denetim Betiğinin (`audit_agent.py`) güvenli, dayanıklı ve standartlara uygun yazılması için uygulanması gereken kod ve konfigürasyon güvenlik denetim listesi** aşağıda sunulmuştur:

---

### 🛡️ `audit_agent.py` İçin Güvenlik ve Konfigürasyon Denetim Listesi

#### 1. Girdi Doğrulama ve Enjeksiyon Koruması (Input Validation & Command Injection)
* **Komut Çalıştırma Riskleri:** Betik içinde `os.system()`, `subprocess.Popen(..., shell=True)` veya `eval()` gibi güvensiz fonksiyonlar kullanılmamalıdır.
* **Girdi Temizleme:** Hedef IP/Domain girdileri düzenli ifadeler (Regex) ile doğrulanmalı; Komut Enjeksiyonu (Command Injection) ve SSRF (Server-Side Request Forgery) riskleri engellenmelidir.
  ```python
  # Hatalı kullanım:
  os.system(f"ping {hedef}")  # Komut enjeksiyonuna açık!

  # Güvenli kullanım:
  subprocess.run(["ping", "-c", "1", hedef_ip], check=True, shell=False)
  ```

#### 2. Ağ İstekleri ve Zamanaşımı (Timeout & Rate Limiting)
* **Zamanaşımı (Timeout):** `requests.get()` veya soket bağlantılarında mutlaka `timeout` parametresi tanımlanmalıdır. Aksi halde betik askıda kalabilir veya Kaynak Tüketim Saldırılarına (DoS) açık hale gelir.
  ```python
  response = requests.get(url, timeout=5)  # Güvenli yaklaşım
  ```
* **SSL Sertifika Doğrulaması:** İsteklerde `verify=False` kullanılmamalıdır. Sertifika doğrulamasını kapatmak Man-in-the-Middle (MiTM) saldırılarına imkan tanır.

#### 3. Hassas Veri Güvenliği ve Bilgi İfşası (Hardcoded Secrets & Logging)
* **Sert Kodlanmış (Hardcoded) Bilgiler:** API anahtarları, parolalar veya yetkilendirme jetonları koda gömülmemeli; ortam değişkenlerinden (`os.getenv`) veya güvenli kasa çözümlerinden çekilmelidir.
* **Hata Yönetimi (Error Handling):** `try-except` bloklarında kullanıcıya veya günlüğe (log) hassas sistem izleri (stack trace) yazdırılmamalı, hata mesajları sanitize edilmelidir.

#### 4. Bağımlılık Güvenliği (Dependency Security)
* Betikte kullanılan kütüphanelerin (`requests`, `urllib3`, `dnspython` vb.) güncel ve bilinen zafiyetlerden (CVE) arındırılmış olduğu doğrulanmalıdır.
* **Denetim Komutu:**
  ```bash
  pip install safety
  safety check -r requirements.txt
  ```

#### 5. En Az Yetki Prensibi (Least Privilege)
* `audit_agent.py` betiği işletim sisteminde `root` / `Administrator` yetkileriyle çalıştırılmamalı, yalnızca gerekli ağ izinlerine sahip düşük yetkili bir kullanıcı hesabıyla yürütülmelidir.

---

### 💡 Özet
Eğer **canlı bir web uygulamasını veya etki alanını** taratmak istiyorsanız, lütfen geçerli bir URL veya domain adresi giriniz (Örn: `https://ornekdomain.com`). 

Eğer `audit_agent.py` betiğinin **kod güvenliği incelemesini** yaptırmak istiyorsanız, ilgili Python kod bloğunu paylaştığınız takdirde Statik Kod Güvenlik Analizi (SAST) gerçekleştirilebilir.