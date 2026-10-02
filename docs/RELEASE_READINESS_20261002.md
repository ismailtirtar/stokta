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
| Yamalı bağımlılıklar | 2 Ekim brace-expansion 1.1.21 / 2.1.7 / 5.0.12 ve undici 6.28.1 aynı ana sürümlerle sabitlendi; temiz npm ci, strict/Edge tipleri, Expo uyumluluğu ve Android dışa aktarımı geçti | Expo SDK yükseltilmedi; node-forge danışmanı hâlâ denetimi başarısız kılıyor |
| Google Play üretim erişimi | 2 Ekim canlı Console: production erişimi GRANTED | Üretim kanalı etkin değil; erişim verilmesi mağazada yayınlandığı anlamına gelmez |
| Etkin Play test sürümleri | 2 Ekim canlı Console: dahili test 1.3.4 (25), 22 Eylül; Alpha 1.3.4 (21), 8 Eylül etkin | main kaynağından üretilen imzalı EAS 1.3.4 (29) Play'e yüklenmiş değildir; mevcut birleşik adayın yeni AAB'si henüz üretilmedi |
| Veri Güvenliği formu düzeltmesi | 2 Ekim satın alma geçmişi ve kullanıcı kimliklerinin toplama/paylaşma yanıtları kaydedildi; yayınlama kuyruğunda “Veri Güvenliği anketi dolduruldu” satırı doğrulandı | Dört değişiklik incelemeye gönderilmeyi bekliyor; otomatik ön kontroller ve Google Play inceleme/onayı tamamlanmadı |
| Public gizlilik politikası | [Gizlilik sayfası](https://stokdas.tirtarhan.chatgpt.site/gizlilik), Sites v17; 2 Ekim 12:59:36.211420 UTC dağıtımı nativeSucceeded. Kaynak `af101394408bec96881036bb490fe6d85c6852e5`, dağıtım `appgdep_6abfaaa5367c81919de595229d93a193` | Koşulsuz 30 gün içinde silme sözü kaldırıldı; mali saklama kararı, destek SLA'sı ve Play formunun inceleme/onayı açık kaldı |

Canlı işlev sürümleri: verify-play-subscription v10, google-play-rtdn v4, google-play-reconcile v3. Token kasasında 3 kayıt var; 6 eski hash-only ledger kaydı periyodik olarak sorgulanamıyor. Bu başlangıç farkı gizlenmemeli.

Mevcut Free planda sızdırılmış parola koruması kapalıdır. Supabase'in bu koruması Pro ve üzeri planlarda sunulur. Mevcut parola kuralları ve hız sınırları aynı korumanın yerine geçtiği olarak değerlendirilmez; yalnız bu uyarı için ücretli yükseltme yapılmadı. `pg_net` uzantısı taşınabilir değildir; danışman uyarısını silmek için yapılandırması değiştirilmedi.

Yerel Android kaynak haritasında node-forge ve @expo/code-signing-certificates yoktur. Kurulu bağımlılık Expo CLI kod imzalama/sertifika doğrulama araçlarında kullanılır. Mobil pakette bulunmaması derleme araçlarının açık güvenlik danışmanını kapatmaz; üretim denetimi ve CI yayın kapısı başarısız kalır.

## Güvenlik denetiminin derleme ve gönderime bağlanması

2 Ekim kaynak incelemesinde `1d5941e` adayının güvenlik denetiminin yalnız `source-quality.yml` içinde çalıştığı görüldü. Aynı HEAD'in [kaynak işi](https://github.com/ismailtirtar/stokta/actions/runs/37050615186) audit nedeniyle başarısızken [Android doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37050615173) ve [Play doğrulaması](https://github.com/ismailtirtar/stokta/actions/runs/37050615231) yalnız tip kontrolüyle başarılı olabiliyordu. Bu PR çalışmaları gerçek build/submit işlerini atladığından önceki başarısız audit tek başına bağımsız yayın işlerinin bu kontrolü zorunlu tuttuğunu kanıtlamıyordu.

`verify:release` bağımlılık denetimi, uygulama/Edge/strict TypeScript, kaynak testleri, Expo bağımlılık kontrolü ve Android dışa aktarımını `&&` ile sıralar. İki yayın workflow'unun `validate` işi bu ön kontrolü zorunlu çalıştırır; `build` ve `submit` yalnız başarılı `validate` sonucundan sonra ilerler. `build:play` komutu EAS isteğinden önce aynı kontrolü çalıştırır; standart EAS Build'deki `eas-build-post-install` hook'u uzak derlemede de kontrolü tekrarlar. Custom EAS build workflow'ları kullanılmamaktadır; yeni bir custom build yolu eklenirse aynı kontrol onun adımlarına da açıkça eklenmelidir. Branch protection/ruleset ayarı değiştirilmedi.

Eski audit denetleyicisine `{}` ve başarılı çıkış kodu verildiğinde yanlışlıkla başarılı sonuç ürettiği yerel süreç testiyle yeniden gösterildi. Güncel denetleyici rapor sürümü, kayıt biçimi, önem derecesi sayaçları, toplam ve çıkış kodunu doğrular; eksik veya tutarsız raporlar reddedilir. Kritik bulgular eski Metro istisnasından yararlanamaz. `node-forge` için istisna, sürüm etiketi değiştirme veya üçüncü taraf fork eklenmedi; lockfile SHA-256 `815f5d0791032b8a8556fd549de1f96e51ff644f5a6ec5f291b174b8670fd092` değişmedi.

Yerel güvenlik regresyonları 29/29 geçti. Ön kontrolün her adımında enjekte edilen başarısızlık sonraki komutları durdurdu; temiz/tutarlı audit raporu kabul edildi, node-forge, bozuk/eksik raporlar ve kritik bulgu reddedildi. Üç TypeScript kontrolü ve Expo uyumluluk kontrolü geçti. Android dışa aktarımı 2.628.887 baytlık Hermes bundle üretti; metadata hedefi, dosyanın dolu olması ve Hermes başlığı doğrulandı. Bu çıktı imzalı AAB değildir. Gerçek `npm run verify:release` açık node-forge danışmanı nedeniyle exit 1 ile durdu; bu beklenen güvenlik engelidir, başarılı yayın doğrulaması değildir.

2 Ekim npm kayıtlarında node-forge'un yayımlanmış güncel sürümü 1.4.0, yeni `@expo/code-signing-certificates` 0.0.7 sürümünün bağımlılığı da `node-forge ^1.4.0` idi. Resmî GHSA danışmanı yamalı sürüm bildirmiyor; upstream önerilen düzeltme PR'ı #1152 henüz açık. `image-size` 2.0.4 yayımlanmış olsa da kurulu Metro 0.83.3'ün varsayılan senkron işlevine dosya yolu gönderen çağrısı yeni API'yle aynı değildir; doğrulanmamış major override eklenmedi. Mevcut belgeli Metro/image-size istisnası genişletilmedi. Güvenli bağımlılık çözümü ve gerçek native/Play/mali saklama kapıları hâlâ açıktır.

## Canlı migrasyon geçmişi eşlemesi

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
| Bağımlılık güvenliği | Üretim bağımlılık denetimi geçmeli. 2 Ekim kontrolünde node-forge için GHSA-86w9-cpqp-85rv açık; resmi danışmanda <=1.4.0 etkilenmiş, yamalı sürüm yok. Denetim istisnası eklenerek gizlenmedi; resmi düzeltme veya doğrulanmış uyumlu bağımlılık değişikliği gerekiyor |
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
