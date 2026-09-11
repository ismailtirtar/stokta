# Google Play yaşam döngüsü v2 — üretim kurulumu

Bu belge `20260911123000_google_play_subscription_lifecycle_v2.sql` ve ilişkili Edge Functions için zorunlu üretim kurulumudur. Migration ve fonksiyonları tek başına dağıtmak yeterli değildir; RTDN push ve iki worker zamanlayıcısı çalışmadan ücretli erişim açılmamalıdır.

## Secret ve IAM

Supabase Edge secret'larına şunları ekleyin; değerleri repoya, migration'a veya cron SQL'ine düz metin yazmayın:

- `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON`: yalnız Android Publisher abonelik görüntüleme/yönetme yetkili servis hesabı JSON'u.
- `GOOGLE_PLAY_TOKEN_ENCRYPTION_KEY`: rastgele 32 byte anahtarın standart Base64 karşılığı. Rotasyon planı olmadan silmeyin.
- `GOOGLE_PLAY_RTDN_AUDIENCE`: Pub/Sub push OIDC audience değerinin tam eşleşmesi.
- `GOOGLE_PLAY_RTDN_SERVICE_ACCOUNT`: push tokenındaki doğrulanmış servis hesabı e-postası.
- `GOOGLE_PLAY_RTDN_SUBSCRIPTION`: `projects/PROJECT_ID/subscriptions/SUBSCRIPTION_ID` tam yolu.
- `GOOGLE_PLAY_RECONCILE_SECRET`: en az 32 karakterlik yalnız worker'a ait rastgele bearer secret.
- `ACCOUNT_AUTH_CLEANUP_SECRET`: en az 32 karakterlik, reconcile secret'ından farklı bearer secret.

`google-play-rtdn` Pub/Sub push aboneliğinde kimliği doğrulanmış push açın; yukarıdaki servis hesabını ve audience değerini birebir kullanın. Handler OIDC imzasını Google tokeninfo üzerinden, issuer/audience/e-posta/son kullanma zamanını ve Pub/Sub subscription yolunu ayrıca doğrular.

`supabase/config.toml` içinde `google-play-rtdn`, `google-play-reconcile` ve `account-auth-cleanup` için `verify_jwt = false` bilinçlidir: Supabase JWT gateway'i Google OIDC veya özel scheduler bearer tokenını kabul etmez. Üç handler da eksik/yanlış kendi kimliğinde `401` ile fail-closed davranır.

## Zorunlu zamanlayıcılar

Tek bir scheduler sahibi seçin. Önerilen düzen:

- Her 5 dakikada bir `POST /functions/v1/google-play-reconcile`, JSON `{"maxJobs":3}`, `Authorization: Bearer <GOOGLE_PLAY_RECONCILE_SECRET>`.
- Her 5 dakikada bir `POST /functions/v1/account-auth-cleanup`, JSON `{"maxJobs":20}`, `Authorization: Bearer <ACCOUNT_AUTH_CLEANUP_SECRET>`.
- Aynı iş adında ikinci cron oluşturmayın. Yeniden kurulumdan önce mevcut job'ı adıyla bulunup güncelleyin veya kaldırın.
- HTTP zaman aşımını reconcile için en az 60 saniye, Auth cleanup için en az 30 saniye yapın. Edge worker kendi 50 saniyelik bütçesinde kalan işi sonraki çalışmaya erteler.

Supabase Cron kullanılıyorsa URL ve bearer secret'ları Vault'ta ayrı secret olarak saklayın. Cron komutu yalnız `vault.decrypted_secrets` üzerinden değerleri okuyup `net.http_post` çağırmalıdır. Dashboard'da job adlarını örneğin `stokdas-google-play-reconcile-v2` ve `stokdas-account-auth-cleanup-v2` olarak sabitleyin. Secret içeren somut SQL'i sürüm kontrolüne eklemeyin.

Harici scheduler kullanılıyorsa aynı tek-aktif-job ve secret ayrımı geçerlidir. Başarısız HTTP yanıtlarında exponential retry uygulayın; aynı anda paralel iki worker tetiklemeyin.

## Dağıtım sırası

1. Tüm migration zincirini boş veritabanında uygula ve fonksiyon imzaları/ACL testini geçir.
2. Secret'ları ve Pub/Sub OIDC IAM ayarlarını oluştur.
3. Edge Functions'ı dağıt; yanlış veya eksik kimliklerin `401`, geçerli özel kimliğin handler'a ulaştığını doğrula.
4. İki beş dakikalık scheduler'ı tekil job adlarıyla etkinleştir.
5. Pub/Sub test bildirimi, lisans test satın alımı, ACK, restore, renewal, hold, cancel, refund/void ve hesap silme senaryolarını çalıştır.
6. Sağlık metrikleri temiz kalmadan gerçek ücretli kullanıcı açma.

## Sağlık ve alarm eşikleri

Service-role ile `public.service_google_play_lifecycle_health()` çıktısını izleyin. Başlangıç alarm eşikleri:

- `rtdnOldestSeconds > 900`: kritik; RTDN hakkı/iadesi gecikiyor.
- `rtdnQuarantined > 0`: inceleme gerekli; deterministik poison bildirim var.
- `observationExpiredLeases > 0` iki cron turu boyunca sürerse worker arızası.
- `authCleanupOldestSeconds > 86400`: kritik; silinmiş DB hesabının Auth kimliği gecikiyor.
- `authCleanupQuarantined > 0`: manuel müdahale gerekli. Bu satırlar kanıtlanmış Auth silme/404 görülmeden otomatik purgedilmez.
- `deletionsProcessing` uzun süre azalmıyorsa aynı canonical `deletionRequestId` ile saga yeniden çalıştırılmalı; `billing_finalized_at` sonrasında fence asla elle kaldırılmamalıdır.

RTDN inbox ve Auth cleanup tabloları Data API'ye kapalı, FORCE RLS ve policy'siz service-only tablolardır. Operatör düzeltmesi doğrudan satır silerek değil, hatanın kök nedenini giderip kontrollü yeniden kuyruğa alma ve lifecycle health doğrulamasıyla yapılmalıdır.
