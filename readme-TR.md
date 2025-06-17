# 🛡️ Mail Güvenlik Analizi - E-posta Güvenlik Tarayıcı Eklentisi

<div align="center">
  <img src="icons/icon128.png" alt="Mail Güvenlik Analizi Logo" width="128" height="128">
  
  [![Version](https://img.shields.io/badge/version-3.0-blue.svg)](https://github.com/yourusername/mail-security-extension)
  [![Chrome](https://img.shields.io/badge/Chrome-Supported-brightgreen.svg)](https://www.google.com/chrome/)
  [![Edge](https://img.shields.io/badge/Edge-Supported-brightgreen.svg)](https://www.microsoft.com/edge)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  
  **Outlook ve Gmail e-postalarınızı gerçek zamanlı olarak analiz eden güvenlik eklentisi**
  
  [English](#english) | [Türkçe](#türkçe) | [Español](#español) | [Deutsch](#deutsch)
</div>

---

## 📋 İçindekiler

1. [Özellikler](#-özellikler)
2. [Kurulum](#-kurulum)
3. [API Anahtarları Alma](#-api-anahtarları-alma)
4. [Kullanım](#-kullanım)
5. [Dil Değiştirme](#-dil-değiştirme)
6. [Klasör Yapısı](#-klasör-yapısı)
7. [Opsiyonel Özellikler](#-opsiyonel-özellikler)
8. [Güvenlik](#-güvenlik)
9. [Sorun Giderme](#-sorun-giderme)
10. [Geliştirme](#-geliştirme)
11. [Lisans](#-lisans)

---

## ✨ Özellikler

### 🔍 Temel Özellikler
- **E-posta Güvenlik Analizi**: Outlook ve Gmail'deki e-postaları otomatik analiz
- **URL Kontrolü**: E-postalardaki tüm linklerin güvenlik taraması
- **Ek Dosya Analizi**: Zararlı ekleri tespit etme
- **Risk Skorlaması**: 0-100 arası detaylı risk puanı

### 🌟 Gelişmiş Özellikler
- **Gönderen Güvenilirlik Kontrolü**
  - SPF/DKIM/DMARC doğrulama
  - Domain yaşı kontrolü
  - IP reputation analizi
- **Çoklu Tehdit İstihbaratı**
  - VirusTotal entegrasyonu
  - AbuseIPDB entegrasyonu (opsiyonel)
- **Çoklu Dil Desteği**
  - 🇬🇧 İngilizce
  - 🇹🇷 Türkçe
  - 🇪🇸 İspanyolca
  - 🇩🇪 Almanca

---

## 🚀 Kurulum

### 📦 Dosyaları İndirme

1. Projeyi bilgisayarınıza indirin:
   ```bash
   git clone https://github.com/yourusername/mail-security-extension.git
   ```
   veya ZIP olarak indirin ve çıkartın.

### 🌐 Chrome'a Kurulum

1. Chrome tarayıcınızı açın
2. Adres çubuğuna `chrome://extensions/` yazın ve Enter'a basın
3. Sağ üst köşedeki **"Geliştirici modu"** anahtarını açın
4. **"Paketlenmemiş öğe yükle"** butonuna tıklayın
5. İndirdiğiniz klasörü seçin (manifest.json dosyasının bulunduğu klasör)
6. Eklenti yüklendi! 🎉

### 🌐 Microsoft Edge'e Kurulum

1. Edge tarayıcınızı açın
2. Adres çubuğuna `edge://extensions/` yazın ve Enter'a basın
3. Sol alttaki **"Geliştirici modu"** anahtarını açın
4. **"Paketi açılmış öğeyi yükle"** butonuna tıklayın
5. İndirdiğiniz klasörü seçin
6. Eklenti yüklendi! 🎉

### 🌐 Opera'ya Kurulum

1. Opera tarayıcınızı açın
2. Adres çubuğuna `opera://extensions/` yazın
3. Sağ üstteki **"Geliştirici modu"** butonunu tıklayın
4. **"Paketi açılmış eklentiyi yükle"** butonuna tıklayın
5. İndirdiğiniz klasörü seçin
6. Eklenti yüklendi! 🎉

---

## 🔑 API Anahtarları Alma

### 1️⃣ VirusTotal API Anahtarı (ZORUNLU)

1. [VirusTotal](https://www.virustotal.com/gui/join-us) sitesine gidin
2. Ücretsiz hesap oluşturun
3. Hesabınıza giriş yapın
4. [API Key sayfasına](https://www.virustotal.com/gui/my-apikey) gidin
5. API anahtarınızı kopyalayın

**Ücretsiz Limit**: Dakikada 4 istek, ayda 500 istek

### 2️⃣ AbuseIPDB API Anahtarı (OPSİYONEL)

1. [AbuseIPDB](https://www.abuseipdb.com/register) sitesine gidin
2. Ücretsiz hesap oluşturun
3. E-posta doğrulaması yapın
4. [API sayfasına](https://www.abuseipdb.com/account/api) gidin
5. "Create Key" butonuna tıklayın
6. API anahtarınızı kopyalayın

**Ücretsiz Limit**: Günde 1000 istek

### 📝 API Anahtarlarını Eklentiye Ekleme

1. Tarayıcı araç çubuğundaki eklenti ikonuna tıklayın
2. **"Ayarlar"** sekmesine geçin
3. VirusTotal API anahtarınızı ilgili alana yapıştırın
4. (Opsiyonel) AbuseIPDB API anahtarınızı ikinci alana yapıştırın
5. **"Kaydet"** butonuna tıklayın

---

## 📖 Kullanım

### Temel Kullanım

1. **Outlook** veya **Gmail** hesabınıza giriş yapın
2. Herhangi bir e-postayı açın
3. Tarayıcı araç çubuğundaki eklenti ikonuna tıklayın
4. **"E-postayı Analiz Et"** butonuna tıklayın
5. Analiz sonuçlarını inceleyin

### Risk Seviyeleri

- 🟢 **Düşük Risk (0-25)**: E-posta güvenli görünüyor
- 🟡 **Orta Risk (25-50)**: Dikkatli olun, şüpheli unsurlar var
- 🔴 **Yüksek Risk (50-100)**: Tehlikeli! Link veya ekleri açmayın

### Demo Test

Eklentiyi test etmek için **"Demo Phishing Testi"** butonunu kullanabilirsiniz. Bu, sahte bir phishing e-postası analizi gösterir.

---

## 🌍 Dil Değiştirme

Eklenti, **tarayıcınızın dil ayarına göre** otomatik olarak dil seçer.

### Chrome'da Dil Değiştirme

1. Chrome Ayarlar'a gidin (⋮ → Ayarlar)
2. Sol menüden **"Gelişmiş"** → **"Diller"**
3. **"Dil"** bölümünü genişletin
4. İstediğiniz dili ekleyin veya sıralamasını değiştirin
5. En üstteki dil eklentide kullanılacaktır
6. Chrome'u yeniden başlatın

### Edge'de Dil Değiştirme

1. Edge Ayarlar'a gidin (⋯ → Ayarlar)
2. Sol menüden **"Diller"**
3. İstediğiniz dili ekleyin ve **"..."** → **"Microsoft Edge'i bu dilde görüntüle"**
4. Edge'i yeniden başlatın

### Desteklenen Diller

- **English** (en) - Varsayılan
- **Türkçe** (tr)
- **Español** (es)
- **Deutsch** (de)

---

## 📁 Klasör Yapısı

```
Chrome Extension/
│
├── 📄 README.md              ← Bu dosya (ana dizine ekleyin)
├── 📄 manifest.json          ← Eklenti yapılandırma dosyası
├── 📄 background.js          ← Arka plan servisi
├── 📄 content.js             ← İçerik scripti (e-posta analizi)
├── 📄 popup.html             ← Eklenti arayüzü
├── 📄 popup.js               ← Eklenti kontrolcüsü
├── 📄 language-manager.js    ← Dil yönetimi (opsiyonel)
│
├── 📁 icons/                 ← Eklenti ikonları
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
└── 📁 _locales/              ← Dil dosyaları
    ├── 📁 en/
    │   └── messages.json     ← İngilizce
    ├── 📁 tr/
    │   └── messages.json     ← Türkçe
    ├── 📁 es/
    │   └── messages.json     ← İspanyolca
    └── 📁 de/
        └── messages.json     ← Almanca
```

---

## ⚙️ Opsiyonel Özellikler

### 1. AbuseIPDB Entegrasyonu

IP reputation kontrolü için AbuseIPDB API'sini etkinleştirebilirsiniz:
- Gönderen IP adresinin kötü niyetli kullanım geçmişi
- Coğrafi konum bilgisi
- ISP bilgisi

### 2. Manuel Dil Seçimi

Varsayılan olarak tarayıcı diline göre çalışır. Manuel dil seçimi eklemek isterseniz:
1. `language-manager.js` dosyasını projeye ekleyin
2. Popup'ta dil seçici aktif olur
3. Kullanıcılar istediği dili seçebilir

### 3. Whitelist/Blacklist (Gelecek Sürüm)

Güvenilir veya engellenecek e-posta adresleri listesi oluşturma özelliği planlanmaktadır.

---

## 🔒 Güvenlik

### Veri Gizliliği

- ✅ E-posta içerikleri **hiçbir yere gönderilmez**
- ✅ Sadece URL'ler ve dosya hash'leri kontrol edilir
- ✅ Tüm analizler **yerel olarak** yapılır
- ✅ API anahtarları **şifreli olarak** saklanır

### İzinler

Eklenti sadece şu izinleri kullanır:
- `activeTab`: Sadece aktif sekmede çalışır
- `storage`: API anahtarlarını saklar
- `dns`: SPF/DMARC kontrolü için

### Güvenlik İpuçları

1. API anahtarlarınızı **kimseyle paylaşmayın**
2. Şüpheli e-postalardaki linklere **tıklamayın**
3. Yüksek riskli ekleri **indirmeyin**
4. Analiz sonuçlarına rağmen **sağduyunuzu kullanın**

---

## 🔧 Sorun Giderme

### "Content script yanıt vermiyor" hatası

1. Sayfayı yenileyin (F5)
2. "Yükle" butonuna tıklayın
3. Eklentiyi kaldırıp tekrar yükleyin

### API anahtarı hataları

1. API anahtarınızın doğru olduğundan emin olun
2. Ücretsiz limitinizi kontrol edin
3. API anahtarını yeniden girin

### Dil değişmiyor

1. Tarayıcı dilini değiştirdikten sonra tarayıcıyı **tamamen kapatıp açın**
2. Eklenti sayfasını yenileyin

---

## 👨‍💻 Geliştirme

### Katkıda Bulunma

1. Projeyi fork'layın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

### Test Etme

```bash
# Eklentiyi geliştirici modunda yükleyin
# Console'da hataları kontrol edin
# Demo testi ile fonksiyonları test edin
```

### Yeni Dil Ekleme

1. `_locales/` klasörüne yeni dil klasörü ekleyin (örn: `fr`)
2. `messages.json` dosyasını İngilizce'den kopyalayın
3. Tüm mesajları çevirin
4. `popup.html` içindeki dil seçiciye ekleyin (opsiyonel)

---

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakınız.

---

## 🙏 Teşekkürler

- [VirusTotal](https://www.virustotal.com) - Güvenlik analizi API'si
- [AbuseIPDB](https://www.abuseipdb.com) - IP reputation API'si
- Tüm katkıda bulunanlar

---

## 📞 İletişim

- **E-posta**: your-email@example.com
- **GitHub**: [github.com/yourusername](https://github.com/yourusername)
- **Issues**: [GitHub Issues](https://github.com/yourusername/mail-security-extension/issues)

---

<div align="center">
  <strong>🛡️ Güvenli e-posta deneyimi için Mail Güvenlik Analizi!</strong>
  
  ⭐ Projeyi beğendiyseniz yıldız vermeyi unutmayın!
</div>