# Stokdaş 1.3.2 — Google Play yayın kontrol listesi

## Hazır olanlar

- [x] Android paket adı sabit: `com.ismailtirtar.stokta`
- [x] Expo SDK 54 / Android target API 36
- [x] Üretim profili AAB üretir ve sürüm kodunu otomatik artırır
- [x] Üretim Supabase bağlantısı yapılandırıldı
- [x] 1024 × 1024 uygulama simgesi ve Android adaptive icon tanımlandı
- [x] 512 × 512 Play simgesi hazırlandı
- [x] 1024 × 500 özellik grafiği hazırlandı
- [x] Uygulama içi gizlilik politikası eklendi
- [x] Çalışan ve yönetici için kalıcı hesap/veri silme akışı eklendi
- [x] Supabase silme işlevi JWT doğrulamasıyla canlıya alındı
- [x] Uygulama içinden güvenli işletme kaydı ve 14 günlük deneme akışı eklendi
- [x] TypeScript ve Android JS üretim dışa aktarımı başarılı

## Kullanıcıdan/Play Console'dan gerekenler

- [ ] Google Play Developer hesabı hazır olmalı
- [ ] Geliştirici destek e-postası kesinleştirilmeli
- [ ] Gizlilik ve hesap silme HTML sayfası herkese açık, sabit bir HTTPS adresinde yayımlanmalı
- [ ] Temiz uygulama ekran görüntüleri alınmalı; şifre veya kişisel veri görünmemeli
- [ ] Play Console'da uygulama oluşturulmalı: Uygulama / Ücretsiz / varsayılan dil Türkçe
- [ ] Uygulama erişimi için geçici bir çalışan inceleme hesabı oluşturulmalı
- [ ] Veri Güvenliği, içerik derecelendirmesi, hedef kitle, reklam ve haber uygulaması beyanları doldurulmalı
- [ ] Üretim AAB'si EAS Build ile oluşturulmalı ve Play Console'a yüklenmeli
- [ ] Kapalı test şartı uygulanıyorsa test tamamlanmalı

## Play Console için önerilen beyanlar

- Reklam içeriyor mu? `Hayır`
- Hedef kitle: `18 yaş ve üzeri / iş kullanıcıları`
- Haber uygulaması mı? `Hayır`
- Sağlık uygulaması mı? `Hayır`
- Finansal özellikler içeriyor mu? `Hayır`
- Uygulama erişimi kısıtlı mı? `Evet — giriş bilgisi gerekli`
- Veri silme: `Uygulama içinde ve web kaynağı üzerinden mevcut`

31 Ağustos 2026'dan itibaren yeni uygulama ve güncellemeler Android 16 / API 36'yı hedeflemelidir. Stokdaş, Expo SDK 54 ile bunu karşılar. Kaynak: [Google Play hedef API şartı](https://support.google.com/googleplay/android-developer/answer/11926878?hl=en).
