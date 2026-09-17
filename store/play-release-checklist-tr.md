# Stokdaş 1.3.4 — Google Play yayın kontrol listesi

## Güncel adayın durumu (11 Eylül 2026)

- Bu depodaki tam denetim adayı henüz Google Play'e yüklenmedi, herhangi bir test kanalında etkinleştirilmedi ve üretim Supabase projesine uygulanmadı.
- Aşağıdaki işaretli eski AAB maddeleri geçmiş yapıların kanıtıdır; güncel kaynak adayının yayımlandığı anlamına gelmez.
- Güncel aday için yeni sürüm kodlu AAB üretilmeli; manifest, imza, Billing Library, temiz kurulum, sunucu migration/Edge dağıtımı ve uçtan uca abonelik testleri yeniden tamamlanmalıdır.

## Hazır olanlar

- [x] Android paket adı sabit: `com.ismailtirtar.stokta`
- [x] Expo SDK 54 / Android target API 36
- [x] Üretim profili AAB üretir ve sürüm kodunu otomatik artırır
- [x] Üretim Supabase bağlantısı yapılandırıldı
- [x] 1024 × 1024 uygulama simgesi ve Android adaptive icon tanımlandı
- [x] 512 × 512 Play simgesi hazırlandı
- [x] 1024 × 500 özellik grafiği hazırlandı
- [x] Uygulama içi gizlilik politikası eklendi
- [x] İçerik oluşturmadan önce `2026-09-11-v2` Kullanım Koşulları sürüm+SHA-256 doğrulamalı kabulü kaynak adayına eklendi
- [x] Ürün, stok hareketi notu ve kullanıcı için uygulama içi bildirme akışı eklendi
- [x] Çalışan içerikleri için işletme yöneticisi, yönetici/platform hedefleri için platform kuyruğu ve gerekçeli/idempotent moderasyon işlemleri kaynak adayına eklendi
- [x] Kullanım koşulları ve gizlilik politikası UGC/bildirim/moderasyon verilerini açıklar
- [x] Çalışan ve yönetici için kalıcı hesap/veri silme akışı eklendi
- [x] Önceki sürümün Supabase silme ve Google Play satın alma doğrulama işlevleri JWT doğrulamasıyla canlıya alınmıştı; güncel yaşam döngüsü v2 adayı için yeniden dağıtım gerekir
- [x] Uygulama içinden güvenli işletme kaydı ve 14 günlük deneme akışı eklendi
- [x] Google Play Billing izni ve Play Billing Library 9.1.0 AAB manifestinde doğrulandı
- [x] TypeScript ve Expo bağımlılık uyumluluk kontrolleri başarılı
- [x] Geçmiş kanıt: imzalı Stokdaş 1.3.4 (18) AAB'si doğrulandı
- [x] Geçmiş kanıt: Stokdaş 1.3.4 (18) Google Play dahili test kanalında etkinleştirildi
- [x] Geçmiş kanıt: Expo IAP 5.5.0 foreground/reconnect uzlaştırmasını içeren Stokdaş 1.3.4 (19) AAB'si üretildi; bundletool, Billing 9.1.0, sürüm kodu ve imza sertifikası doğrulandı
- [x] Geçmiş kanıt: aylık base plan seçimi sağlamlaştırılmış Stokdaş 1.3.4 (20) AAB'si üretildi; EAS build `776cb3fb-290d-4ba9-adde-3b0b39a4484b`, SHA-256 `32ef0c550103951f8162f9e31f2155f5e997b03ef959ee370cc126a0678414c1`, paket/imza/SDK/manifest kontrolleri geçti

## Google Play ve ödeme kurulumu

- [x] Google Play Developer hesabı ve Stokdaş uygulama kaydı hazır
- [ ] Mevcut Google ödeme profili geliştirici hesabına açık kullanıcı onayıyla bağlanmalı
- [ ] Google Cloud Android Publisher servis hesabı ve JSON anahtarı oluşturulmalı
- [ ] Servis hesabına Play Console'da finansal veri görüntüleme ile sipariş/abonelik yönetme izinleri verilmeli
- [ ] Android Publisher doğrulama hesabı JSON'u yalnız Supabase `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` secret'ına eklenmeli; EAS gönderimi gerekiyorsa ayrı ve daha dar yetkili bir hesap/anahtar kullanılmalı
- [x] `stokdas_pro` abonelik ürünü ile `monthly` otomatik yenilenen base plan Google Play Console'da oluşturuldu ve etkinleştirildi
- [x] Türkiye'de yeni aboneler için aylık fiyat KDV dahil 299,99 TL olarak kaydedildi (ticari karar: aylık 300 TL; Google Play fiyat gösterimi)
- [ ] Türkiye dışındaki satış ülkeleri/bölgeleri ve yerel fiyatlar kesinleştirilmeli; mevcut 174 bölge kapsamı bu fiyat değişikliğinde değiştirilmedi
- [ ] Varsa 199,99 TL eski fiyattaki mevcut aboneler için fiyat geçişi ayrıca planlanmalı; Google Play yeni fiyatı otomatik olarak yalnız yeni abonelere uygular
- [ ] Dahili test hesabı ayrıca License Tester listesine eklenmeli
- [ ] Kaynaktaki Google Play RTDN / Pub/Sub alıcısı, mesaj tekrar önleme, reconcile worker ve yaşam döngüsü v2 migration/Edge işlevleri üretime dağıtılmalı; zamanlayıcı, Pub/Sub kimlik doğrulaması ve secret'lar doğrulanmalı
- [ ] `supabase/GOOGLE_PLAY_LIFECYCLE_SETUP.md` sırasıyla uygulanmalı: yedi Edge secret'ı tanımlanmalı, Pub/Sub push OIDC audience/e-posta/tam subscription yolu doğrulanmalı ve secret'lar repo dışında tutulmalı
- [ ] Tekil `stokdas-google-play-reconcile-v2` ve `stokdas-account-auth-cleanup-v2` job'ları her 5 dakikada bir çalışmalı; ikinci/paralel scheduler bulunmadığı kanıtlanmalı
- [ ] `service_google_play_lifecycle_health()` için alarm kurulmalı: RTDN gecikmesi 15 dakika, Auth cleanup gecikmesi 24 saat, herhangi poison/Auth dead-letter sıfırdan büyük olduğunda uyarı vermeli
- [ ] `google-play-rtdn`, `google-play-reconcile` ve `account-auth-cleanup` fonksiyonlarında gateway `verify_jwt=false` iken eksik/yanlış özel kimliğin handler içinde `401` aldığı; doğru OIDC/bearer kimliğinin gateway'i geçip işlediği staging'de doğrulanmalı
- [ ] Sunucu tek ACK otoritesi olan satın alma doğrulama, durable intent, deletion-proof saklama ve hesap silme akışları uçtan uca sınanmalı; mobil istemcinin Android'de ikinci kez ACK çağırmadığı kaynak+AAB üzerinde doğrulanmalı
- [ ] Yarış matrisi geçmeli: T0 ve A/B iki yanıt sırası, geç kalan süresi dolmuş writer, aynı generation divergent yaşam döngüsü, bilinmeyen kötü niyetli claim, crash recovery, void-before-grant, iki aynı-token RTDN, begin→uygulama kapanışı→yeni UUID ile canonical silme resume ve Google/outage sırasında silme fence'i
- [ ] Stokdaş 1.3.4 (20) AAB'si temiz Play Console taslağına iç AAB dosyası olarak yüklenip dahili testte etkinleştirilmeli (kod 19 genel yükleme hatasıyla paket kitaplığına kaydolmadı; kod 18 etkin)
- [ ] İlk satın alma, pending, restore, yenileme, iptal, grace/hold/recovery, refund/revoke ve hesap silme yarış testleri geçmeli
- [ ] RTDN testleri tamamlanana kadar yalnız lisans test hesapları kullanılmalı; gerçek ücret açılmamalı

## Mağaza beyanları

- [ ] Geliştirici destek e-postası kesinleştirilmeli
- [ ] Güncel gizlilik ve hesap silme HTML sayfası `https://stokdas.com/gizlilik#hesap-ve-veri-silme` adresinde herkese açık olarak yayımlanıp Play Console'da doğrulanmalı
- [ ] Temiz uygulama ekran görüntüleri alınmalı; şifre veya kişisel veri görünmemeli
- [ ] Uygulama erişimi için inceleme hesabı oluşturulmalı; ilk girişte `2026-09-11-v2` Kullanım Koşulları kabul edilerek ürün/hareket bildirme, işletme yönetici kuyruğu ve platform kuyruğu doğrulanmalı
- [ ] Veri Güvenliği formunda kullanıcı tarafından oluşturulan içerik, içerik bildirimi, moderasyon kayıtları ve satın alma geçmişi doğru beyan edilmeli
- [ ] Veri Güvenliği formundaki `Finansal bilgiler > Satın alma geçmişi` beyanı; purchase token/hash, sipariş/iade/abonelik yaşam döngüsü ve Google Play/Supabase hizmet sağlayıcı işlemesiyle yayımlanan gizlilik metnine birebir eşlenmeli
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
