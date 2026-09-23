# Google Play yaşam döngüsü kurulumu

Bu değişiklik mevcut Android `{ purchaseToken, productId }` isteğini ve
`service_record_google_play_subscription` imzasını korur. Veritabanı geçişi,
Edge Functions, Pub/Sub ve zamanlayıcı ayrı adımlardır. Yalnız kaynak kodun
birleştirilmesi yaşam döngüsünü etkinleştirmez.

## Hazırlık ve dağıtım sırası

1. `20260923090000_google_play_lifecycle_reconciliation.sql` geçişini
   boş/izole veritabanında mevcut tüm migration zincirinden sonra çalıştırın.
   Eski RPC imzasını, `service_role` dışındaki EXECUTE izinlerini, private
   tablolarda FORCE RLS'yi ve ilk satın alma ile mevcut token güncellemesini
   sınayın. Ayrıca eski token → yeni token devri, ACK öncesi/sırası yarış,
   B bekleyen alımı iptal → C yeniden alım → geç gelen B gözlemi yarışı,
   terk edilmiş bekleyen tokenın tekrar hak açmaması, bağımsız başka geçerli
   aboneliğin korunması ve profil/kuruluş silinmesinde kasa ile ilişki
   özetlerinin cascade temizliğini sınayın. Geçiş, beklenmeyen eski RPC
   gövdesinde bilinçli olarak hata verir.
2. Supabase Edge secret'larını ekleyin:
   `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` (mevcut Publisher servis hesabı),
   `GOOGLE_PLAY_TOKEN_ENCRYPTION_KEY` (tam 32 rastgele byte'ın standart
   Base64 karşılığı), `GOOGLE_PLAY_RECONCILE_SECRET` (en az 32 rastgele
   karakter), `GOOGLE_PLAY_RTDN_AUDIENCE` (tam push URL/audience),
   `GOOGLE_PLAY_RTDN_SERVICE_ACCOUNT` (push OIDC hesabının e-postası) ve
   `GOOGLE_PLAY_RTDN_SUBSCRIPTION`
   (`projects/PROJECT/subscriptions/SUBSCRIPTION` tam yolu). Sırları repoya,
   Cron SQL metnine veya loglara yazmayın. Şifreleme anahtarını, kasa kayıtları
   var oldukça saklayın; anahtar rotasyonu yeni sürüm/migrasyon gerektirir.
3. `google-play-rtdn` ve `google-play-reconcile` Edge Function'larını
   kaynak sürümüyle dağıtın; henüz Play topic yayınını ve zamanlayıcıyı
   etkinleştirmeyin. Bunlar gateway JWT doğrulamasını kapatır, kendi Google
   OIDC / gizli bearer kontrolünü yapar. Eksik/yanlış kimlikle 401,
   bozuk yapılandırmada 503 yanıtını test edin.
4. Google Cloud Pub/Sub topic oluşturup
   `google-play-developer-notifications@system.gserviceaccount.com` hesabına
   yalnız bu topic için Pub/Sub Publisher verin. Kimliği doğrulanmış push
   subscription'ı Edge URL'ye bağlayın; özel servis hesabı e-postası ve
   audience yukarıdaki secret'larla birebir eşleşsin. Pub/Sub service agent'a
   bu servis hesabı için OIDC token oluşturma yetkisi verin. Push ack deadline
   90 saniye, retry ve dead-letter topic (ör. 20 başarısız teslimat) kurun;
   teslim edilmeyen mesajlar ile dead-letter sayısını izleyin. Play Console
   RTDN ayarını ilk iade taraması bitene kadar etkinleştirmeyin.
5. İzole prova ve diğer yayın kapıları geçince canlı migration'ı uygulayın.
   İade taraması tam ve son 15 dakika içinde başarılı olana kadar Play hak
   açma çağrıları 503 döner. Mevcut hakların süresi değişmez; yeni satın alma
   doğrulaması bu sürede gecikir. Tarama için hemen adım 6'yı tamamlayın.
   Kesintisiz yeni satın alma garantisi için ayrı aşamalı veri geçişi gerekir;
   bu sürümün dağıtım kapısıdır.
6. Tek bir `stokdas-google-play-reconcile` zamanlayıcısı kurun; her 5
   dakikada bir `POST /functions/v1/google-play-reconcile` çağırmalı.
   `Authorization: Bearer <GOOGLE_PLAY_RECONCILE_SECRET>` değerini Supabase
   Vault'tan okuyun. `pg_cron` + `pg_net` veya tek bir harici scheduler
   kullanın; aynı isimli ikinci işi kurmayın. HTTP timeout en az 60 saniye
   olsun. Yanıt 5xx ve dead-letter alarmlarını etkinleştirin. HTTP 200
   yanıtındaki `failed > 0` için de alarm kurun: tekil token hataları diğer
   tokenları durdurmadan ertelenir. `service_google_play_lifecycle_health()`
   içindeki `voidLastCompletedAt` 10 dakikadan eskiyse uyarın (15 dakikada
   Play grant kapanır); `overdueCount` ve `failedDueCount` artışlarını ve
   `unvaultedCount` başlangıç değerini izleyin. İlk 29 günlük taramayı hemen
   elle tetikleyin; çok sayfalıysa son sayfaya kadar tekrarlayın.
   `voidLastCompletedAt` dolmadan yeni hak doğrulamasını tamamlanmış saymayın.
7. `verify-play-subscription` Edge Function'ını kaynak sürümüyle dağıtın;
   Supabase JWT gerektirir. Play Console > Monetization setup > Real-time
   developer notifications ayarında abonelik/ürün bildirimlerini etkinleştirip
   topic'in `projects/PROJECT/topics/TOPIC` yolunu girin. Şu an kutu kapalı ve
   topic boş. Test notification gönderin; handler 204 dönmeli ve hak
   değişmemeli.
8. Önce Play lisans test hesabıyla satın alma/ACK ve restore, ardından
   yenileme, dönem sonu iptal, grace/hold, süresi dolmuş aboneliğin uygulama
   ve Play Store üzerinden yeniden alınması, bekleyen alımın iptali sonrası
   tekrar deneme, iade edilen son sipariş, eski döneme ait iade, Pub/Sub
   yeniden teslimatı ve onaylı IBAN dönemi
   senaryolarını sınayın. Her senaryoda Google API durumu, private ledger,
   kuruluş erişimi ve `service_google_play_lifecycle_health()` çıktısını
   karşılaştırın. Operatör TOTP/AAL2 ve normal yönetici/çalışan girişlerini
   ayrıca kontrol edin.
9. **Açık test yayın kapısı:** Play Console taban planında “Yeniden abone ol”
   şu an “İzin ver”. Bu dal, Google'ın `linkedPurchaseToken` ve
   `outOfAppPurchaseContext.expiredPurchaseToken` alanlarını eski tokenın
   değişmez ledger sahibiyle eşleştirip yeni tokenı yalnız aynı kullanıcı ve
   işletmeye bağlar; ACK öncesinde ilişkiyi kaydeder, ardından Google'dan
   tekrar okur. Eski token ve başarısız bekleyen kardeş tokenlar hash çitiyle
   kalıcı olarak grant dışında tutulur. İzole SQL transaction/yetki/silme
   provası ve gerçek Play lisans testleri geçmeden bu kodu canlıya dağıtmayın.

## Çalışma ve sınırlar

- RTDN bir durum kararı değildir: handler Google'ın
  `purchases.subscriptionsv2.get` yanıtını ve hesap/ürün/plan eşleşmesini
  yeniden doğrular. Pub/Sub 2xx yanıtı yalnız başarılı işleme veya bilinmeyen
  token/bozuk mesaj için verilir; geçici Google/veritabanı hatası 503 ile
  yeniden teslimata bırakılır.
- İlk satın almada mobil uygulamanın mevcut doğrulama isteği kayıt sahipliğini
  oluşturur. Bilinmeyen RTDN tokenında Google doğrulanmış önceki tokenı
  döndürürse önceki ledger sahibine aynı kullanıcı/işletme/kimlik özetleriyle
  bağlanabilir; önceki ledger yoksa hak veya ACK açmadan 204 ile bırakılır.
  Sıfırdan alımda istemci callback'i hiç ulaşmazsa satın alma ACK edilmez;
  kullanıcı uygulamadan `Satın alımları geri yükle` yolunu kullanmalıdır.
  Bu durumu bir test satın alımında özellikle gözlemleyin.
- Ham purchase token yalnız AES-GCM şifreli olarak `private` kasada durur.
  Kasa kaydı otomatik süre sonunda silinmez; ilgili abonelik ledger satırı
  silinirse FK ile birlikte silinir. Yerine-geçme ve terk edilmiş token hash
  çitleri tekil ledger silinmesinde korunur, profil/kuruluş silinmesinde
  cascade ile silinir; bu hash çitlerine otomatik süre temizliği uygulanmaz.
  Etkin bir aboneliğin önceki tokenına ait ledger satırını elle tek başına
  silmeyin: yeni tokenın sonraki uzlaştırması önceki sahipliği yeniden
  doğrulayamaz. Olağan hesap/işletme silme işlemi ilişkili satırları birlikte
  temizlemelidir; bunu izole veritabanında ayrıca sınayın.
  Ledger kuruluş/profil silinmesine bağlıdır,
  fakat bu değişiklik hesap silme iş akışı veya ayrıca bir saklama süresi
  eklemez. İade çitindeki token/sipariş SHA-256 özetleri ve gözlem kilidi
  özetleri için de otomatik temizleme yoktur. Mobil hesap metni ve gizlilik
  politikası bu gerçek durumu yansıtmadan dağıtıma geçmeyin.
  Eski hash-only kayıtlar RTDN veya mobil geri yükleme geldiğinde kasaya
  eklenir; hash'ten geriye token çıkarılamaz. Sağlık çıktısındaki
  `unvaultedCount` sıfıra yaklaşana kadar bu hesaplarda periyodik sorgu
  mümkün değildir.
- Uzlaştırma önce Voided Purchases API'nin tüm sayfalarını kaydeder, yalnız
  son sayfa tamamlanınca bilinen tokenları GET ile yeniler. SQL'deki ortak
  grant kapısı mobil/RTDN yollarını da tam ve son 15 dakikalık taramaya
  bağlar. İade taraması başarısızsa yeni Play hakkı vermez.
  İlk tarama 29 günlük pencereyi kullanır; sonraki tam turlarda 2 günlük
  örtüşme vardır. 29 günden uzun kesinti logda alarm gerektirir, çünkü
  Google API daha eski void kayıtlarını getiremez.
- `suspended` hesaplar otomatik açılmaz. Mevcut 7 günlük inaktif dönemin
  sonundaki askı ve idari askı aynı alanı kullandığından otomatik reaktivasyon
  ayrı bir ürün/veri modeli kararı gerektirir. Play HOLD/PAUSED/PENDING
  durumları `past_due` olur ve Play hakkı kapanır; mevcut cron bunları yedi
  gün sonra `suspended` yapmaz. Aynı token Google'da iyileşip ACTIVE/ACK
  olursa tekrar açılabilir. Geçerli onaylı IBAN dönemi Play HOLD sırasında
  da korunur. HOLD için ayrıca 7 günlük otomatik askı isteniyorsa idari ve
  fatura kaynaklı askı nedenlerini ayıran yeni şema/test gerekir.
- İade edilen son Google siparişi için onaylı IBAN dönemi varsa işletmenin
  bitişi o IBAN tarihine indirilir; iade edilmiş Google dönemi hakkı uzatmaz.

## Kaynaklar

- Google Play RTDN: https://developer.android.com/google/play/billing/rtdn-reference
- Google Play abonelik yaşam döngüsü:
  https://developer.android.com/google/play/billing/lifecycle/subscriptions
- Voided Purchases API:
  https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.voidedpurchases/list
- Pub/Sub authenticated push:
  https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions
- Supabase scheduled Edge Functions:
  https://supabase.com/docs/guides/functions/schedule-functions
