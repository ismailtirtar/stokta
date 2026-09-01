# Stokdaş 1.3.4 — Google Play yayın kontrol listesi

## Hazır olanlar

- [x] Android paket adı sabit: `com.ismailtirtar.stokta`
- [x] Expo SDK 54 / Android target API 36
- [x] Üretim profili AAB üretir ve sürüm kodunu otomatik artırır
- [x] Üretim Supabase bağlantısı yapılandırıldı
- [x] 1024 × 1024 uygulama simgesi ve Android adaptive icon tanımlandı
- [x] 512 × 512 Play simgesi hazırlandı
- [x] 1024 × 500 özellik grafiği hazırlandı
- [x] Uygulama içi gizlilik politikası eklendi
- [x] İçerik oluşturmadan önce 2026-08-29-v1 Kullanım Koşulları kabulü eklendi
- [x] Ürün, stok hareketi notu ve kullanıcı için uygulama içi bildirme akışı eklendi
- [x] İşletme yöneticileri için bildirim inceleme ve ölçülü moderasyon işlemleri eklendi
- [x] Kullanım koşulları ve gizlilik politikası UGC/bildirim/moderasyon verilerini açıklar
- [x] Çalışan ve yönetici için kalıcı hesap/veri silme akışı eklendi
- [x] Supabase silme ve Google Play satın alma doğrulama işlevleri JWT doğrulamasıyla canlıya alındı
- [x] Uygulama içinden güvenli işletme kaydı ve 14 günlük deneme akışı eklendi
- [x] Google Play Billing izni ve Play Billing Library 9.1.0 AAB manifestinde doğrulandı
- [x] TypeScript ve Expo bağımlılık uyumluluk kontrolleri başarılı
- [x] İmzalı Stokdaş 1.3.4 (18) AAB'si doğrulandı
- [x] Stokdaş 1.3.4 (18) Google Play dahili test kanalında etkinleştirildi
- [x] Expo IAP 5.5.0 foreground/reconnect uzlaştırmasını içeren Stokdaş 1.3.4 (19) AAB'si üretildi; bundletool, Billing 9.1.0, sürüm kodu ve imza sertifikası doğrulandı
- [x] Aylık base plan seçimi sağlamlaştırılmış Stokdaş 1.3.4 (20) AAB'si üretildi; EAS build `776cb3fb-290d-4ba9-adde-3b0b39a4484b`, SHA-256 `32ef0c550103951f8162f9e31f2155f5e997b03ef959ee370cc126a0678414c1`, paket/imza/SDK/manifest kontrolleri geçti

## Google Play ve ödeme kurulumu

- [x] Google Play Developer hesabı ve Stokdaş uygulama kaydı hazır
- [ ] Mevcut Google ödeme profili geliştirici hesabına açık kullanıcı onayıyla bağlanmalı
- [ ] Google Cloud Android Publisher servis hesabı ve JSON anahtarı oluşturulmalı
- [ ] Servis hesabına Play Console'da finansal veri görüntüleme ile sipariş/abonelik yönetme izinleri verilmeli
- [ ] Android Publisher doğrulama hesabı JSON'u yalnız Supabase `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` secret'ına eklenmeli; EAS gönderimi gerekiyorsa ayrı ve daha dar yetkili bir hesap/anahtar kullanılmalı
- [ ] `stokdas_pro` abonelik ürünü ile `monthly` otomatik yenilenen base plan oluşturulup etkinleştirilmeli
- [ ] Aylık TRY fiyatı ve satış yapılacak ülkeler kesinleştirilmeli
- [ ] Dahili test hesabı ayrıca License Tester listesine eklenmeli
- [ ] Google Play RTDN / Pub/Sub alıcısı, mesaj tekrar önleme ve yaşam döngüsü eşitlemesi tamamlanmalı; review-ready taslak canlıya alınmadı
- [ ] Mevcut satın alma doğrulama ve hesap silme Edge akışları durable ACK/deletion-lease protokolüne taşınmalı; recovery/refund worker, gizlilik metni ve branch yarış testleri tamamlanmalı
- [ ] Stokdaş 1.3.4 (20) AAB'si temiz Play Console taslağına iç AAB dosyası olarak yüklenip dahili testte etkinleştirilmeli (kod 19 genel yükleme hatasıyla paket kitaplığına kaydolmadı; kod 18 etkin)
- [ ] İlk satın alma, pending, restore, yenileme, iptal, grace/hold/recovery, refund/revoke ve hesap silme yarış testleri geçmeli
- [ ] RTDN testleri tamamlanana kadar yalnız lisans test hesapları kullanılmalı; gerçek ücret açılmamalı

## Mağaza beyanları

- [ ] Geliştirici destek e-postası kesinleştirilmeli
- [ ] Gizlilik ve hesap silme HTML sayfası herkese açık, sabit bir HTTPS adresinde yayımlanmalı
- [ ] Temiz uygulama ekran görüntüleri alınmalı; şifre veya kişisel veri görünmemeli
- [ ] Uygulama erişimi için inceleme hesabı oluşturulmalı; ilk girişte Kullanım Koşulları kabul edilerek ürün/hareket bildirme ve yönetici inceleme akışı doğrulanmalı
- [ ] Veri Güvenliği formunda kullanıcı tarafından oluşturulan içerik, içerik bildirimi, moderasyon kayıtları ve satın alma geçmişi doğru beyan edilmeli
- [ ] İçerik derecelendirmesi, hedef kitle, reklam ve haber uygulaması beyanları doldurulmalı
- [ ] Kapalı test şartı uygulanıyorsa test tamamlanmalı

## Play Console için önerilen beyanlar

- Reklam içeriyor mu? `Hayır`
- Hedef kitle: `16-17 ve 18 yaş ve üzeri / iş kullanıcıları`
- Haber uygulaması mı? `Hayır`
- Sağlık uygulaması mı? `Hayır`
- Finansal özellikler içeriyor mu? `Hayır — ancak Google Play satın alma geçmişi abonelik sağlamak için işlenir`
- Uygulama erişimi kısıtlı mı? `Evet — giriş bilgisi gerekli`
- Veri silme: `Uygulama içinde ve web kaynağı üzerinden mevcut`

1 Eylül 2026 itibarıyla Google Play Billing kullanan yeni uygulama ve güncellemeler en az Play Billing Library 8 içermelidir. Stokdaş AAB'sinde 9.1.0 doğrulandı. Android hedef API 36'dır.
