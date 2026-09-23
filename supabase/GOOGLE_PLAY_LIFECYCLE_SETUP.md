# Google Play yaşam döngüsü kurulumu

Bu değişiklik mevcut Android `{ purchaseToken, productId }` isteğini ve
`service_record_google_play_subscription` imzasını korur. Veritabanı geçişi,
Edge Functions, Pub/Sub ve zamanlayıcı ayrı adımlardır. Yalnız kaynak kodun
birleştirilmesi yaşam döngüsünü etkinleştirmez.

## Dağıtım sırası

1. `20260923090000_google_play_lifecycle_reconciliation.sql` geçişini önce
   boş/izole veritabanında mevcut tüm migration zincirinden sonra çalıştırın.
   Eski RPC imzasını, `service_role` dışındaki EXECUTE izinlerini, private
   tablolarda FORCE RLS'yi ve ilk satın alma ile mevcut token güncellemesini
   sınayın. Geçiş, beklenmeyen eski RPC gövdesinde bilinçli olarak hata verir.
   Canlı geçişte iade taraması tam ve son 15 dakika içinde başarılı olana
   kadar Play hak açma çağrıları bilinçli olarak 503 döner. Mevcut hakların
   süresi değişmez; yeni satın alma/yenileme doğrulaması bu sürede gecikir.
   Sırları, topic/subscription'ı ve zamanlayıcıyı geçişten önce hazırlayın;
   geçiş sonrası hemen taramayı başlatıp çok sayfalı tarama bitene dek tekrar
   çağırın. Sağlık çıktısında `voidLastCompletedAt` dolmadan canlı
   doğrulamayı tamamlanmış saymayın. Kesintisiz yeni satın alma garantisi
   için ayrıca aşamalı veri geçişi gerekir; bu sürümün dağıtım kapısıdır.
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
3. `verify-play-subscription`, `google-play-rtdn` ve
   `google-play-reconcile` Edge Function'larını kaynak sürümüyle dağıtın.
   İlk fonksiyon Supabase JWT gerektirir. Diğer ikisi gateway JWT doğrulamasını
   kapatır ve kendi Google OIDC / gizli bearer kontrolünü yapar. Eksik/yanlış
   kimlikle 401, bozuk yapılandırmada 503 yanıtını test edin.
4. Google Cloud Pub/Sub topic oluşturup
   `google-play-developer-notifications@system.gserviceaccount.com` hesabına
   yalnız bu topic için Pub/Sub Publisher verin. Kimliği doğrulanmış push
   subscription'ı Edge URL'ye bağlayın; özel servis hesabı e-postası ve
   audience yukarıdaki secret'larla birebir eşleşsin. Pub/Sub service agent'a
   bu servis hesabı için OIDC token oluşturma yetkisi verin. Push ack deadline
   90 saniye, retry ve dead-letter topic (ör. 20 başarısız teslimat) kurun;
   teslim edilmeyen mesajlar ile dead-letter sayısını izleyin.
5. Play Console > Monetization setup > Real-time developer notifications:
   abonelik/ürün bildirimlerini etkinleştirip topic'in
   `projects/PROJECT/topics/TOPIC` yolunu girin. Şu an kutu kapalı ve topic
   boş olduğundan bu adım zorunlu. Test notification gönderin; handler test
   mesajını 204 ile kabul etmeli ve veritabanında hak değişmemeli.
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
   `unvaultedCount` başlangıç değerini izleyin.
7. Önce Play lisans test hesabıyla satın alma/ACK ve restore, ardından
   yenileme, dönem sonu iptal, grace/hold, iade edilen son sipariş, eski
   döneme ait iade, Pub/Sub yeniden teslimatı ve onaylı IBAN dönemi
   senaryolarını sınayın. Her senaryoda Google API durumu, private ledger,
   kuruluş erişimi ve `service_google_play_lifecycle_health()` çıktısını
   karşılaştırın. Operatör TOTP/AAL2 ve normal yönetici/çalışan girişlerini
   ayrıca kontrol edin.
8. **Açık test yayın kapısı:** Play Console taban planında “Yeniden abone ol”
   şu an “İzin ver”. `linkedPurchaseToken` ve
   `outOfAppPurchaseContext.expiredPurchaseToken` içeren yeni tokenlar bu
   sürümde güvenli hesap devri kurulamadığından 409 ile reddedilir; yeni
   ücretli işlem ACK alamayabilir. Yeni token devri Google tarafından
   doğrulanmış eski token sahipliğiyle uygulama+SQL düzeyinde test edilmeden
   veya Play Console'da bu akışların tümünün engellendiği (hold/erken tekrar
   alım dahil) gerçek satın alma testleriyle doğrulanmadan dağıtmayın.
   “Yeniden abone ol” seçeneğini tek başına kapatmak yeterli kabul edilmez.

## Çalışma ve sınırlar

- RTDN bir durum kararı değildir: handler Google'ın
  `purchases.subscriptionsv2.get` yanıtını ve hesap/ürün/plan eşleşmesini
  yeniden doğrular. Pub/Sub 2xx yanıtı yalnız başarılı işleme veya bilinmeyen
  token/bozuk mesaj için verilir; geçici Google/veritabanı hatası 503 ile
  yeniden teslimata bırakılır.
- İlk satın almada mobil uygulamanın mevcut doğrulama isteği kayıt sahipliğini
  oluşturur. Bundan önce gelen bilinmeyen RTDN tokenı erişim açmaz ve 204 ile
  bırakılır. İstemci callback'i hiç ulaşmazsa satın alma ACK edilmez; kullanıcı
  uygulamadan `Satın alımları geri yükle` yolunu kullanmalıdır. Bu durumu
  bir test satın alımında özellikle gözlemleyin.
- Ham purchase token yalnız AES-GCM şifreli olarak `private` kasada durur.
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
  ayrı bir ürün/veri modeli kararı gerektirir.
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
