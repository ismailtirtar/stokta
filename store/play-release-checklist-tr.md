# Stokdaş 1.3.4 — Google Play yayın kontrol listesi

3 Ekim 2026 gönderim ön kontrolü: imzalı 1.3.4 (31), main `e06b5b08` kaynağından
üretildi ve paket/imza/bütünlük kontrolleri geçti. Yeni braces danışmanı nedeniyle
yenilenen güvenlik kontrolü gönderimi durdurdu; bu paket Play'e yüklenmedi.
Güncel kanıt ve açık kapılar için `../docs/RELEASE_READINESS_20261002.md` esas alınır.

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
- [x] Atomik silme ve ödeme bağlantılı talep incelemesi canlı delete-account v16'da; index.ts ve ortak security.ts yayın adayıyla SHA-256 bazında aynı. Auth temizliği beş dakikada bir çalışıyor; son dört HTTP yanıtı 200, pending=0 ve withFailures=0 (3 Ekim 00:42 TSİ)
- [ ] Çalışan/yönetici gerçek cihaz silme akışları ve ödeme kayıtlı talebin nihai saklama/silme kararı yeni Android paketiyle tamamlanmalı; boş Auth kuyruğu gerçek silme işlemi kanıtı değildir
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
- [x] Google Play yaşam döngüsü arka ucu canlı: verify-play-subscription v10, google-play-rtdn v4, google-play-reconcile v3; 1 Ekim gerçek satın alma/ACK/restore/yenileme/iptal ve etkin refund/revoke provası geçti
- [ ] Pub/Sub expiration/retry/dead-letter/alarmlar, gerçek Play Store üzerinden yeniden abonelik ve grace/hold/recovery tamamlanmalı; 2 Ekim Google Cloud bu bulut oturumunda erişilemedi
- [x] Birleşik 053a5f7 adayında kaynak, Android/Play doğrulaması ve iki izole DB provası PASS; 139 kaynak testi ve payment/delete/refund yarışları geçti. Canlı delete-account v16 ve aktif Auth outbox cron'u ayrıca doğrulandı
- [x] İzole SQL provasında gerçek web ödeme onayıyla oluşan IBAN süresi Play hold/expiry/refund sonrasında korundu; eski sipariş iadesi güncel sipariş hakkını kapatmadı. Bu Google lisans testlerinin yerine geçmez
- [ ] braces güvenlik düzeltmesi sonrası tam kontrolü geçen kaynaktan yeni imzalı AAB üretilmeli; commit/paket/sürüm/imza eşleşmesi doğrulanıp dahili teste o paket gönderilmeli. 31 numaralı önceki aday yeni bulgu nedeniyle gönderilmedi. 2 Ekim Console gözleminde dahili testte 1.3.4 (25), Alpha'da 1.3.4 (21) etkin; önceki 18/19/20 kayıtları tarihsel kanıttır
- [ ] İlk satın alma, pending, restore, yenileme, iptal, grace/hold/recovery, refund/revoke ve hesap silme yarış testleri geçmeli
- [ ] RTDN testleri tamamlanana kadar yalnız lisans test hesapları kullanılmalı; gerçek ücret açılmamalı

## Mağaza beyanları

- [ ] Geliştirici destek e-postası kesinleştirilmeli
- [ ] Gizlilik ve hesap silme HTML sayfası herkese açık, sabit bir HTTPS adresinde yayımlanmalı
- [ ] Temiz uygulama ekran görüntüleri alınmalı; şifre veya kişisel veri görünmemeli
- [ ] Uygulama erişimi için inceleme hesabı oluşturulmalı; ilk girişte Kullanım Koşulları kabul edilerek ürün/hareket bildirme ve yönetici inceleme akışı doğrulanmalı
- [ ] Açık test incelemesi öncesi canlı Play Console Veri Güvenliği beyanı okunup `Finansal bilgiler > Satın alma geçmişi`, şifreli satın alma belirteci ve silme/saklama akışıyla karşılaştırılmalı; gerekiyorsa form güncellenip onay durumu doğrulanmalı (bkz. `google-play-data-safety-tr.md`)
- [ ] Veri Güvenliği formunda kullanıcı tarafından oluşturulan içerik, içerik bildirimi ve moderasyon kayıtları doğru beyan edilmeli
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
