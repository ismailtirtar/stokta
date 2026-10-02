# Stokdaş ilk kararlı yayın doğrulaması

Bu belge doğrulanmış sonuçları ve açık kapıları ayırır. Kaynak CI testleri gerçek Google Play lisans testlerinin yerine geçmez. Bir PR'ın taslak olması veya bir AAB'ın derlenmesi, canlı sürümün yayınlandığı anlamına gelmez.

## Doğrulanmış sonuçlar

| Kontrol | Kanıt | Sınır |
|---|---|---|
| İlk satın alma ve ACK | 1 Ekim gerçek lisans testi; ACK öncesi hak kapalı, ACK sonrası açık | Yeni birleşik Android sürümü ayrıca sınanmalı |
| Geri yükleme, yenileme, dönem sonu iptal | 1 Ekim Google API, ledger ve telefon gözlemleri | Uygulama dışından yeniden alım ayrı kapıdır |
| Etkin aboneliği iade edip hakkını kaldırma | 1 Ekim 17:20:29 UTC gerçek test siparişi; 17:20:36 UTC hak kapandı, 17:21:00 UTC yazma reddedildi; önceki bitiş 17:22:58 UTC | Gerçek para işlemi yapılmadı; lisans test siparişi |
| Verilerin okunabilir kalması ve yazmanın kapanması | Kullanıcının 1 Ekim 20:23 telefon ekranları | “Ödeme bekliyor” etiketi Google PENDING durumunu kanıtlamaz |
| Canlı periyodik uzlaştırma | DB gözlemi 2 Ekim 05:12:50 UTC; etkin 5 dakikalık cron, son altı iş başarılı; overdueCount=0, failedDueCount=0, void taraması 05:10:01 UTC | Cron başarılı kaydı tek başına HTTP işleme kanıtı değildir; sağlık çıktısıyla birlikte değerlendirildi |
| Operatör MFA ve yetki sınırı | 2 Ekim READ ONLY + ROLLBACK matrisi 7/7: oturumsuz, iptal edilmiş oturum, yanlış rol, AAL1 veya TOTP AMR eksikliği reddedildi; gerçek TOTP/AAL2 operatör okumaya yetkili. 18 hassas tabloda anon/authenticated CRUD erişimi yok; servis RPC'leri bu rollere kapalı | Hosted MFA kayıt/doğrulama ayarları bu oturumda okunmadı; yeni Android sürümünde rol davranışları ayrıca sınanmalı |
| Yamalı bağımlılıklar | 2 Ekim brace-expansion 1.1.21 / 2.1.7 / 5.0.12 ve undici 6.28.1 sabitlendi; node-forge 1.4.0 kaynak ve iki browser dosyasında kontrollü yerel yamayla doğrulandı. Temiz npm ci ve tam verify:release geçti | Resmî node-forge sürümü hâlâ etkilenmiş; yerel azaltım 2 Kasım sonunda yeniden inceleme gerektirir. Metro/image-size için önceki ayrı istisna devam eder |
| Google Play üretim erişimi | 2 Ekim canlı Console: production erişimi GRANTED | Üretim kanalı etkin değil; erişim verilmesi mağazada yayınlandığı anlamına gelmez |
| Etkin Play test sürümleri | 2 Ekim canlı Console: dahili test 1.3.4 (25), 22 Eylül; Alpha 1.3.4 (21), 8 Eylül etkin | main kaynağından üretilen imzalı EAS 1.3.4 (29) Play'e yüklenmiş değildir; mevcut birleşik adayın yeni AAB'si henüz üretilmedi |
| Veri Güvenliği formu düzeltmesi | 2 Ekim satın alma geçmişi ve kullanıcı kimliklerinin toplama/paylaşma yanıtları kaydedildi; yayınlama kuyruğunda “Veri Güvenliği anketi dolduruldu” satırı doğrulandı | Dört değişiklik incelemeye gönderilmeyi bekliyor; otomatik ön kontroller ve Google Play inceleme/onayı tamamlanmadı |
| Public gizlilik politikası | [Gizlilik sayfası](https://stokdas.tirtarhan.chatgpt.site/gizlilik), Sites v17; 2 Ekim 12:59:36.211420 UTC dağıtımı nativeSucceeded. Kaynak `af101394408bec96881036bb490fe6d85c6852e5`, dağıtım `appgdep_6abfaaa5367c81919de595229d93a193` | Koşulsuz 30 gün içinde silme sözü kaldırıldı; mali saklama kararı, destek SLA'sı ve Play formunun inceleme/onayı açık kaldı |

Canlı işlev sürümleri: verify-play-subscription v10, google-play-rtdn v4, google-play-reconcile v3. Token kasasında 3 kayıt var; 6 eski hash-only ledger kaydı periyodik olarak sorgulanamıyor. Bu başlangıç farkı gizlenmemeli.

Mevcut Free planda sızdırılmış parola koruması kapalıdır. Supabase'in bu koruması Pro ve üzeri planlarda sunulur. Mevcut parola kuralları ve hız sınırları aynı korumanın yerine geçtiği olarak değerlendirilmez; yalnız bu uyarı için ücretli yükseltme yapılmadı. `pg_net` uzantısı taşınabilir değildir; danışman uyarısını silmek için yapılandırması değiştirilmedi.

Yerel Android kaynak haritasında node-forge ve @expo/code-signing-certificates yoktur. Kurulu bağımlılık Expo CLI kod imzalama/sertifika doğrulama araçlarında kullanılır. Mobil pakette bulunmaması derleme araçlarının danışmanını kapatmaz; aşağıdaki kontrollü yama, bu araçların gerçekten kullandığı kurulu dosyaları ve imza davranışını doğrular.

## Güvenlik denetiminin derleme ve gönderime bağlanması

2 Ekim kaynak incelemesinde `1d5941e` adayının güvenlik denetiminin yalnız `source-quality.yml` içinde çalıştığı görüldü. Aynı HEAD'in [kaynak işi](https://github.com/ismailtirtar/stokta/actions/runs/37050615186) audit nedeniyle başarısızken [Android doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37050615173) ve [Play doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37050615231) yalnız tip kontrolüyle başarılı olabiliyordu. Bu PR çalışmaları gerçek build/submit işlerini atladığından önceki başarısız audit tek başına bağımsız yayın işlerinin bu kontrolü zorunlu tuttuğunu kanıtlamıyordu.

`verify:release` bağımlılık denetimi, uygulama/Edge/strict TypeScript, kaynak testleri, Expo bağımlılık kontrolü ve Android dışa aktarımını `&&` ile sıralar. İki yayın workflow'unun `validate` işi bu ön kontrolü zorunlu çalıştırır; `build` ve `submit` yalnız başarılı `validate` sonucundan sonra ilerler. `build:play` komutu EAS isteğinden önce aynı kontrolü çalıştırır; standart EAS Build'deki `eas-build-post-install` hook'u uzak derlemede de kontrolü tekrarlar. Custom EAS build workflow'ları kullanılmamaktadır; yeni bir custom build yolu eklenirse aynı kontrol onun adımlarına da açıkça eklenmelidir. Branch protection/ruleset ayarı değiştirilmedi.

Eski audit denetleyicisine `{}` ve başarılı çıkış kodu verildiğinde yanlışlıkla başarılı sonuç ürettiği yerel süreç testiyle yeniden gösterildi. Güncel denetleyici rapor sürümü, kayıt biçimi, önem derecesi sayaçları, toplam ve çıkış kodunu doğrular; eksik veya tutarsız raporlar reddedilir. Kritik bulgular geçici istisnalardan yararlanamaz. Önceki `a100c112` commit'inde node-forge için bir istisna veya yama yoktu; o aşamada lockfile SHA-256 `815f5d0791032b8a8556fd549de1f96e51ff644f5a6ec5f291b174b8670fd092` değişmemişti. Sonraki yerel yama ayrı kapsamıyla aşağıda belgelenir.

Önceki `a100c112` aşamasında yerel güvenlik regresyonları 29/29 geçti. Ön kontrolün her adımında enjekte edilen başarısızlık sonraki komutları durdurdu; temiz/tutarlı audit raporu kabul edildi, yamasız node-forge, bozuk/eksik raporlar ve kritik bulgu reddedildi. Üç TypeScript kontrolü ve Expo uyumluluk kontrolü geçti. Android dışa aktarımı 2.628.887 baytlık Hermes bundle üretti; metadata hedefi, dosyanın dolu olması ve Hermes başlığı doğrulandı. Bu çıktı imzalı AAB değildir. O aşamada gerçek `npm run verify:release` açık node-forge danışmanı nedeniyle exit 1 ile durdu; bu önceki engel sonucu güncel yama doğrulaması olarak gösterilmez.

2 Ekim npm kayıtlarında node-forge'un yayımlanmış güncel sürümü 1.4.0, yeni `@expo/code-signing-certificates` 0.0.7 sürümünün bağımlılığı da `node-forge ^1.4.0` idi. Resmî GHSA danışmanı yamalı sürüm bildirmiyor; upstream önerilen düzeltme PR'ı #1152 henüz açık. `image-size` 2.0.4 yayımlanmış olsa da kurulu Metro 0.83.3'ün varsayılan senkron işlevine dosya yolu gönderen çağrısı yeni API'yle aynı değildir; doğrulanmamış major override eklenmedi. Mevcut belgeli Metro/image-size istisnası genişletilmedi. Gerçek native/Play/mali saklama kapıları hâlâ açıktır.

## node-forge kontrollü yerel yamasının doğrulanması

Kullanıcının güvenli çözümü uygulama talebiyle node-forge tam `1.4.0` sürümüne sabitlendi. `postinstall` kaynak ve iki dağıtılmış browser dosyasındaki nested `DigestAlgorithm` eleman sayımını düzeltir. Kaynak dosyanın son içeriği upstream PR #1152'nin `ceba34402e329f0365134f23fe19898756527d65` commit'iyle bayt bazında eşleşir. Resmî tarball'ın SHA-512 bütünlüğü ve 59 özgün dosya doğrulanarak manifest üretildi; üç değişen dosyada özgün/yamalı SHA-256 kayıtlıdır. Sürüm etiketi değişmez, fork eklenmez.

Üretim audit kapısı, dosya envanterini/özetlerini, lockfile sürümünü/kaynağını/bütünlüğünü ve Expo tüketicilerinin gerçekten çözdüğü node-forge yollarını kontrol eder. Ardından kaynak ve iki browser girişinde e=3 ve e=65537 ile 60 RSA ayrıştırma vakasını yeniden çalıştırır. Bu doğrulama başarılıysa yalnız GHSA-86w9-cpqp-85rv ve bilinen Expo zinciri yerel olarak azaltılmış sayılır. Ham npm audit yine beş high paket ve sıfır critical raporlar; sonuç sıfır açık veya resmî yamalı sürüm olarak sunulmaz. Metro istisnası ayrı kalır. Yeni high/critical danışman, değişmiş kapsam, eksik yama veya sürenin dolması yayını durdurur.

| Yerel kontrol | Sonuç |
|---|---|
| `npm ci --ignore-scripts` + gerçek production audit | Yamasız dosya nedeniyle exit 1; yayın kapısı doğru şekilde kapandı |
| Normal temiz `npm ci` | postinstall otomatik yama, 59 dosya bütünlüğü ve 60 RSA vakası PASS |
| Özgün paketin negatif kontrolü | Üç girişte ve iki üs değerinde nested fazlalık, beklenmeyen parametre ve yinelenen NULL kabulü tekrar gösterildi; yama sonrasında hepsi reddedildi |
| Tam `npm run verify:release` | Audit, üç TypeScript kontrolü, 139/139 test, Expo uyumluluğu ve 674 modüllük Android Hermes export PASS |
| Expo kod imzalama uyumluluğu | Gerçek sertifika/PEM/CSR ve imza API'leri PASS; Node crypto bağımsız doğrulaması kabul, değiştirilmiş mesaj ret |
| Değiştirilmiş/eksik dosya, sembolik bağlantı, yeni lock kaynağı/kopyası/tüketicisi | Reddedildi; kontrol değiştirilmiş dosyayı otomatik onarmadı |

Lockfile içindeki paket sürümleri ve kaynakları değişmedi; yalnız kök `hasInstallScript` eklendi. Yeni lockfile SHA-256 `0f54dc21fdc5d7dc80757bb0654619cadc74d52935341a05b9646b8ef29da720`. Android bundle'ın Hermes başlığı ve dolu metadata hedefi ayrıca doğrulandı. Yerel export imzalı AAB veya Play yüklemesi değildir. Bu tablo yerel sonuçları gösterir; [PR #22](https://github.com/ismailtirtar/stokta/pull/22) üzerindeki son HEAD kontrolleri ayrıca kontrol edilmelidir.

Yama kararı **2 Kasım 2026 sonunda UTC** sona erer; kurulum ve denetim yeniden inceleme olmadan geçmez. Resmî düzeltme yayımlanınca aynı imza/Expo testleriyle uyumluluk doğrulanıp bu geçici yama ve koşullu audit kapsamı kaldırılmalıdır. Ayrıntılar, kaynaklar ve kaldırma adımları [node-forge yama belgesindedir](../security/node-forge-patch.md). Bozuk imzalar geçici test özel anahtarlarıyla oluşturulur; testler özel anahtar olmadan yeni bir forgery saldırısı gösterimi veya bütün kriptografinin ispatı değildir.

## 3 Ekim 00:42 TSİ cihaz testi öncesi doğrulama

`053a5f771c10e68d733446110b1402c734392d04` adayının beş GitHub kontrolü PASS: [kaynak](https://github.com/ismailtirtar/stokta/actions/runs/37067356825), [Android doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37067356674), [Play doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37067356693), [abonelik DB provası](https://github.com/ismailtirtar/stokta/actions/runs/37067356728), [silme DB provası](https://github.com/ismailtirtar/stokta/actions/runs/37067356722). PR olayında imzalı build ve mağaza gönderimi atlandı; bu sonuçlar imzalı yeni AAB kanıtı değildir.

Mevcut `supabase/tests/google_play_lifecycle_regression.sql` gerçek SQL hizmet işlevleriyle IBAN onayını, Play hold/expiry/refund sonrasında bağımsız web süresinin korunmasını ve eski sipariş iadesinin güncel siparişi kapatmamasını sınar. Son HEAD'in izole DB provasına bu dosya dahildir. Gerçek Google grace/hold/recovery ve Play Store üzerinden yeniden abonelik lisans testleri ayrıca açık kalır.

2 Ekim 21:41 UTC (3 Ekim 00:41 TSİ) canlı kaynaktan okunan delete-account **v16**, JWT doğrulaması açıkken yayın adayının iki dosyasıyla bayt bazında eşleşir: index.ts SHA-256 `51a7e261fab2b19409b2fd7752027714836929c7fdc927246fc4bdff6ed9b17b`, ortak security.ts `0ce50585d3df42db4b1514a2673eefa5e2aa2e988511888955c4c57efb9f4d9c`. Bu nedenle eski kontrol listesindeki v13 kaydı güncel durum olarak kullanılamaz.

21:42:03 UTC sağlık gözleminde hesap silme Auth kuyruğu pending=0/withFailures=0. `stokdas-account-deletion-auth-cleanup` ve `stokdas-google-play-reconcile` etkin ve beş dakikalıktır. 21:25, 21:30, 21:35 ve 21:40 UTC cron kayıtları başarılı; iki işin bu sekiz HTTP yanıtı 200 ve timeout=false. Auth yanıtları processed=0/pending=false; Play yanıtları failed=0/moreVoidPages=false. Play sağlık çıktısında lifecycleActive=true, overdueCount=0, failedDueCount=0, voidLastCompletedAt=21:40:01 UTC; önceden belgelenen altı kasasız eski ledger kaydı devam eder. Boş kuyruk gözlemi gerçek kullanıcı hesabının uçtan uca silindiği anlamına gelmez.

Bu aşamada sıradaki adım başarılı kaynak adayını main ile birleştirip tek imzalı Android test paketini üretmektir. Mevcut workflow main push'unda güvenlik kontrolünden sonra AAB derler; Play gönderimi yalnız manuel workflow_dispatch ile çalışır. Gerçek cihaz/saklama/bildirim/Console kapıları açık kalır.

## Canlı migrasyon geçmişi eşlemesi (2 Ekim gözlemi)

2 Ekim yalnız okuma karşılaştırmasında 26 canlı geçmiş kaydı ve 21 kaynak dosyası incelendi: 18 ad, 3 özgün sürüm zaman damgası ve 12 tam SQL SHA-256 özeti eşleşti.
Adı eşleşen 6 SQL içerik farkı açık kaldı: `store_account_deletion`, `self_service_registration`, `google_play_subscription_billing`, `google_play_subscription_authoritative_entitlement`, `google_play_subscription_runtime_fix`, `platform_operator_write_access`.
Yalnız kaynakta bulunan 3 ad: `platform_operator_mfa_aal2`, `web_payment_notifications`, `inactive_payment_grace_period`; yalnız canlı geçmişte bulunan 8 ad: 3 müşteri migrasyonu, 4 tek seferlik gönderim migrasyonu ve `enable_pg_net_for_google_play_reconcile`.

| Migrasyon | Kaynak sürümü | Canlı geçmiş sürümü | Aynı SQL SHA-256 |
|---|---|---|---|
| `atomic_account_deletion_payment_guard` | `20261002060744` (eski ad: `20260924165747`) | `20261002060744` | `d6559ccef2ef38ae875feba154aa5a4eaeefe547166d8352d92fd75552cba1b5` |
| `google_play_lifecycle_reconciliation` | `20260923090000` | `20260929214535` | `25d385fd78ca16866a7edf70bec5b2a1217c56586fa47b07c95f32be222dda7c` |

Yalnız atomik silme dosyasının kimliği hizalandı; tek SQL ifadesinin içeriği ve canlı geçmiş değiştirilmedi. Diğer dosyalar, özellikle runtime düzeltmeleri arasındaki kronoloji değişebileceğinden yeniden adlandırılmadı.
CLI `db push` ve dry-run çalıştırılmadı; eski geçmiş farkları uzlaştırılmadan genel dağıtım güvenli sayılmaz.
Önceki aday `4e0a02d` için [silme DB provası](https://github.com/ismailtirtar/stokta/actions/runs/37009494323) ve [Google Play DB provası](https://github.com/ismailtirtar/stokta/actions/runs/37009494352) geçti: tam migrasyon replay'i, silme/ödeme yarışının iki kilit sırası ve Google Play iade yarışı doğrulandı. [Kaynak workflow'unda](https://github.com/ismailtirtar/stokta/actions/runs/37009494309) 82/82 test, tip denetimleri, Expo uyumluluğu ve Android Hermes dışa aktarımı geçti; yalnız node-forge güvenlik denetimi başarısız, imzalı build ve gönderim adımları atlandı.
Sonraki iki belge değişikliği runtime, test ve SQL içeriğini değiştirmez; bu önceki commit kanıtları, sonraki commit'in son HEAD CI sonucu olarak gösterilmez.

## Açık yayın kapıları

| Kapı | Tamamlanma ölçütü |
|---|---|
| Kaynak bütünlüğü | Güncel main ile #17/#20/#21 ve gizlilik/silme düzeltmeleri birleştirilmeli; main'deki destek yönlendirmesi korunmalı; birleşik commit'in tüm CI kontrolleri geçmeli |
| Bağımlılık güvenliği | Kontrollü node-forge yamasıyla yerel üretim denetimi ve tam verify:release PASS. Son HEAD CI da geçmeli; yamalı dosya bütünlüğü ve gerçek RSA vakaları her kurulum/yayında korunmalı. Yerel karar 2 Kasım sonunda dolar; resmî düzeltmeye geçiş ve önceki ayrı Metro/image-size istisnası takip edilmeli |
| Play Store üzerinden yeniden abonelik | Gerçek lisans testinde yeni tokenın eski değişmez sahibine bağlandığı, ACK aldığı ve doğru işletmenin erişiminin açıldığı gösterilmeli |
| Ödeme başarısızlığı ve düzelmesi | Gerçek grace/hold/recovery testinde grace erişimi korunmalı, hold yazmayı kapatmalı, ACTIVE/ACK iyileşmesi erişimi açmalı |
| Bekleyen satın alma iptali ve tekrar deneme | Gerçek Google testinde bekleyen/terk edilmiş token hak açmamalı; sonraki başarılı satın alma doğru hesaba bağlanmalı |
| IBAN ile birlikte kullanım | İzole DB provasında onaylı bağımsız IBAN dönemi Play hold/expiry/refund sonrasında korunmalı; eski sipariş iadesi yeni geçerli siparişi iptal etmemeli |
| Hesap silme | Atomik DB işlemi, kalıcı Auth cleanup retry, PDF/audit temizliği ve bağımsız yenilenen abonelik kontrolü sınanmalı; ödeme bağlantılı silme talebi tamamlanabilir, açık ve yetkili inceleme yoluna sahip olmalı |
| Saklama ve gizlilik | Kaynak politikada 30 gün içinde koşulsuz silme sözü değerlendirme/yanıt yükümlülüğü olarak düzeltildi; aynı düzeltmeyi içeren public Sites v17 yayını doğrulandı. Şifreli token saklama, satın alma geçmişi ve mali kayıtların silme/inceleme davranışı uygulama, public politika ve Play Veri Güvenliği beyanıyla eşleşmeli; çözümlenmemiş mali saklama kararı ve destek SLA'sı ile Play formunun inceleme/onayı tamamlandı sayılmamalı |
| Bildirim dayanıklılığı | Push kimliği/audience korunarak expiration/retry/dead-letter/alarmlar canlı Google Cloud üzerinden doğrulanmalı |
| Yeni Android sürümü | Tam CI geçen commit'ten tek imzalı AAB derlenmeli; artifact/commit/versionCode eşleşmeli; dahili testte o sürüm kurulup temel akışlar doğrulanmalı |
| Açık test | Güncel Play Console koşulları ve dahili test sonuçları doğrulanıp sürüm açık teste ilerletilmeli; yeni cihaz/kullanıcı geri bildirimi alınmalı |

2 Ekim bulut tarayıcısı Google Cloud için “Site Unavailable” döndürdü. Bu, ayarların doğrulandığı veya hizmetin genel olarak kapalı olduğu anlamına gelmez.

## Kaynaklar

- https://developer.android.com/google/play/billing/test
- https://developer.android.com/google/play/billing/lifecycle/subscriptions
- https://support.google.com/googleplay/android-developer/answer/13327111?hl=en-EN
- https://github.com/advisories/GHSA-86w9-cpqp-85rv

Bu yayın kapıları kapanmadan proje %100 tamamlandı olarak işaretlenmez.
