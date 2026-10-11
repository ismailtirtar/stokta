# node-forge 1.4.0 yerel güvenlik yaması

## Durum — 11 Ekim 2026

İç `DigestAlgorithm` eleman sayımına ek olarak, içerik taşıyan NULL parametresi ve standart dışı DER uzunluk kodlamalarının kabulü yeniden üretildi ve aşağıdaki dar kapsamlı yama ile giderildi. Eski yama yeni kodlama vakalarının 84/84'ünü varsayılan doğrulamada kabul ediyordu. Yeni yama bunları ana kaynakta ve iki dağıtım bundle'ında reddeder. Bu sonuç, bütün kriptografik uygulamanın güvenli olduğunun veya özel anahtar olmadan imza sahteciliğinin kanıtı değildir.

**Bu ayrı değişiklik node-forge'a özgü geçici yayın engelini kaldırır.** Güvenlik düzeltmesi [PR #28](https://github.com/ismailtirtar/stokta/pull/28) ve `af3b2f5668926d49e3b76b1f6927669c5ea51306` kaynağında engel korunarak doğrulandı. Kaynak CI'da 196 test, üç tip kontrolü, çevrimiçi Expo uyumluluğu ve Android export geçti; üç iş akışının audit adımları yalnız kasıtlı engelde durdu. Bu sonraki değişiklik koşulsuz engel dosyasını ve onun üç politika testini kaldırır. `audit:production` normal rapor, danışman/graph ve iki yama bütünlüğü/davranış denetimlerini korur. `verify:release`, CI ve EAS ön kontrolleri zorunludur. Sürüm sabitlemesi, tüketiciler, lockfile, audit istisnaları ve 2 Kasım inceleme tarihi değiştirilmemiştir. Bu, Play'de yayınlandığı anlamına gelmez.

11 Ekim kontrolünde npm'in güncel node-forge sürümü 1.4.0'dır; [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv) yamalı sürüm belirtmez ve [upstream PR #1152](https://github.com/digitalbazaar/forge/pull/1152) açık durumdadır. Bu çalışma resmî veya birleştirilmiş upstream düzeltmesi değildir.

## İncelenen Android paketi ve kullanım kapsamı

[Android iş akışı 37739716103](https://github.com/ismailtirtar/stokta/actions/runs/37739716103) içindeki `stokdas-1.3.4-33-android-aab` artefaktı indirildi. ZIP, AAB, EAS build kaydı ve `release-provenance.json` birbirleriyle eşleştirildi.

| Alan | Doğrulanan değer |
| --- | --- |
| GitHub artefakt kimliği | `11533283686` |
| EAS build kimliği | `8c0c580e-a802-4253-89f7-50df06da1d4e` |
| Kaynak commit | `ba1e5e52dd28b31edbffbb1ecb386ae55c708625` |
| EAS sonuç / profil / SDK | `FINISHED` / `production` / `54.0.0` |
| AAB manifesti | `com.ismailtirtar.stokta`, sürüm `1.3.4`, versionCode `33` |
| ZIP SHA-256 | `70511ba059e9692bb0b9d90e2cc7663ee2d9f83d9f4e247806bfe87183e6b4aa` |
| AAB SHA-256 | `28adaee8ba93527b94c6601973a843a03dda1db5556444df4f34df5ff484e156` |

AAB'nin protobuf Android manifesti doğrudan çözüldü. JAR manifestindeki 767 imzalı içerik girdisinin SHA-256 özetleri, `.SF` manifest özeti ve `.RSA` CMS imzası doğrulandı. Yükleme sertifikasının SHA-256 parmak izi `62:31:49:46:50:E3:58:44:E3:A2:F4:C2:BA:98:0D:44:25:66:26:EF:0B:1D:B8:C8:86:8E:3B:7A:98:8C:1F:87`'dir. CMS doğrulaması sertifika güven zincirini veya Play App Signing sertifikasını doğrulamaz.

Paketteki `base/assets/index.android.bundle`, Hermes bytecode sürümü 96 olarak ayrıştırıldı: 10.603 fonksiyon, 11.409 string ve 496 fonksiyon kaynak girdisi. Bytecode string/fonksiyon dökümünde `DigestInfo`, `algorithmIdentifier`, `node-forge`, `forge.pki`, `generateSelfSignedCodeSigningCertificate`, `modInverse` ve `asn1` işaretleri bulunmadı. AAB'nin 770 ZIP girdisinin ham taraması da bu işaretleri göstermedi. Tek DEX ve 60 yerel `.so` girdisi bu arşiv taramasına dahildir; bu işlem tam yerel kod tersine mühendisliği değildir.

Kaynak ve lockfile incelemesi node-forge'un yalnız `@expo/code-signing-certificates` 0.0.6 ve Expo içindeki `@expo/cli` 54.0.27 tarafından çözüldüğünü gösterir. Uygulama kaynaklarında doğrudan node-forge import'u, yapılandırmada `expo-updates` veya code signing ayarı yoktur. İncelemenin tabanı `ca0cc784569a0cf26a638589821966ccbd7682f4` ile AAB kaynak commit'i arasında uygulama kodu/lockfile değişmemiş; yayın engeli, test ve belge değişiklikleri vardır. Yerel Android export'unun 673 source-map kaynağında da node-forge ve `@expo/code-signing-certificates` yoktur. Bu kanıtlar, incelenen sürümde Forge'un Expo geliştirme/build araçlarında kaldığı sonucunu destekler.

Bu, imzalı EAS AAB 33 incelemesidir. Google'ın ürettiği APK, Play Console'daki güncel üretim kanalı/inceleme durumu ve cihazdaki kurulum bu çalışma kapsamında doğrulanmadı. Yerel Hermes export'u AAB 33 ile bayt bazında eşleşmez; yeniden üretilebilir derleme kanıtı olarak sunulmaz. GitHub artefaktının mevcut son kullanma tarihi 7 Kasım 2026'dır.

## Düzeltme ve kurulum

İç eleman sayımı upstream önerisinin `ceba34402e329f0365134f23fe19898756527d65` commit'ine dayanır. İki ek kontrol yerel inceleme sonucudur; yeni `lib/rsa.js` upstream önerisiyle bayt bazında aynı değildir:

1. İsteğe bağlı ASN.1 NULL mevcutsa yakalanan içerik tam olarak boş olmalıdır.
2. Ayrıştırılan `DigestInfo`, DER ile yeniden kodlanır ve imzadaki özgün baytlarla karşılaştırılır. Böylece gereksiz long-form, baştaki sıfır uzunluk okteti ve BER indefinite uzunlukları reddedilir. Varsayılan doğrulama tüm DigestInfo baytlarını karşılaştırır.

Upstream'in test amaçlı `_parseAllDigestBytes: false` seçeneği için mevcut sonek toleransı korunur; bu seçenek ayrıştırılan bölümün DER önekiyle karşılaştırılmasını kullanır. İki yeni kontrol bu seçenekle de aktiftir. Boş NULL, SHA-384/SHA-512 ve mevcut SHA-256 parametresiz uyumluluk davranışı korunur. Node/OpenSSL parametresiz SHA-256 vakasını kabul etmediği için bu tek uyumluluk vakası bağımsız doğrulayıcıyla eşitlik iddiasına dahil değildir. MD5 vakası mevcut ayrıştırma uyumluluğunu sınar; yeni kriptografi tercihi önermez.

Kontroller yalnız RSA PKCS#1 v1.5 imza doğrulamasında uygulanır. Genel ASN.1 ayrıştırıcısı ve sertifika/CSR ayrıştırma kuralları değiştirilmez. Aynı koşullar `dist/forge.min.js` ve `dist/forge.all.min.js` içinde de uygulanır; bundle'lar yeniden derlenmez. Yerel değişikliklerin kuralları [RFC 8017, §9.2 ve Ek B.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2) ile karşılaştırıldı.

`security/node-forge-patch.json`, sürüm, registry URL'si, SHA-512 tarball bütünlüğü, tüketiciler, üç kesin metin değişikliği ve 59 paket dosyasının SHA-256 özetlerini içerir. Değişen üç dosyanın yamalı özetleri yenilenmiştir; özgün paket özetleri korunur. `upstreamCommit` eleman sayımının referansıdır; `localReview` ek kontrollerin yerel olduğunu belirtir.

`package.json` tam `1.4.0` override'ını korur. `npm ci`/`npm install`, `postinstall` içinde yama denetimini çalıştırır. Betik tüm envanteri ve kilidi kontrol eder; yalnız bilinen özgün dosyaları yamalar ve ikinci çalıştırmada aynı içeriği korur. Bilinmeyen içerik, eksik/ek dosya, sembolik bağlantı, kaynak/sürüm veya tüketici değişikliği reddedilir. Tüketicilerin gerçekten çözdüğü Forge kopyası `createRequire(...).resolve(...)` ile denetlenir; kilit dışında kalan iç içe kopya da reddedilir. `--check` yamayı uygulamaz veya onarmaz.

## Davranış ve uyumluluk kanıtı

Her yama denetimi üç girişte, e=3/e=65537 ve geçici 2048 bit test anahtarlarıyla **228 gerçek RSA vakası** yürütür: 30 kabul ve 198 ret. Bozuk uzunluklar bağımsız ham TLV kodlayıcısıyla hazırlanır; Forge serializer'ının bunları testten önce düzeltmesine izin verilmez.

- Önceki 10 pozitif/negatif biçim korunur: geçerli digest'ler, iç/dış fazladan elemanlar, beklenmeyen parametre, yinelenen NULL ve yanlış digest.
- 14 yeni bozuk biçim vardır: bir ve 16 oktet içerikli NULL; DigestInfo, DigestAlgorithm, OID, NULL ve digest alanlarının her biri için gereksiz long-form ve sıfırla başlayan uzunluk; iki SEQUENCE için indefinite uzunluk.
- Yeni bozuk biçimler varsayılan seçenekle ve `_parseAllDigestBytes: false` ile sınanır. Eski yama her iki seçenek grubunun 84/84'ünü kabul eder; yeni yama 168/168'ini reddeder.
- Parametresiz SHA-256 uyumluluğu dışında tüm sonuçlar Node/OpenSSL'in bağımsız doğrulamasıyla aynı olmalıdır. Beklenen ret yerine alakasız çalışma zamanı hatası oluşursa denetim başarısız olur.
- Altı regresyon testi, NULL veya DER kontrolünü üç girişin her birinden tek tek çıkarır ve manifest hash'ini yeniden hesaplar. Böylece hash doğru olsa bile davranış denetiminin eksik güvenlik kontrolünü yakaladığı gösterilir.
- Özgün 1.4.0 paketinin açıkları kabul ettiği, yamanın temiz kurulumda uygulandığı ve yeniden uygulamanın değişiklik yapmadığı ayrıca sınanır.

11 Ekim'de Node 22.23.3 ile tamamlanan doğrulama:

| Kontrol | Sonuç |
| --- | --- |
| Temiz `npm ci --no-audit --no-fund` | 721 paket; Forge 59 hash / 228 vaka ve mevcut braces denetimi başarılı |
| `node scripts/node-forge-patch.mjs --check` | 59 hash ve 228 RSA vakası başarılı |
| `node --test tests/*.test.mjs` | 196/196 geçti; önceki 190 teste altı güvenlik mutasyon testi eklendi |
| Upstream v1.4.0 RSA/ASN.1/CSR/PKCS1/X509 testleri | 384 geçti, upstream'de tanımlı 4 test atlandı, 0 hata |
| Expo sertifika/PEM/CSR/SHA-256 akışı | Gerçek Expo API'siyle başarılı; imza Node crypto ile doğrulandı, değişmiş mesaj reddedildi |
| TypeScript / strict-unused / Edge Function tip kontrolleri | Üçü de başarılı |
| `EXPO_OFFLINE=1 EXPO_NO_TELEMETRY=1 expo install --check` | Yerel SDK uyumluluk eşlemesi başarılı; güncel uzak sürüm listesi sorgulanmadı |
| Kullanıcı izniyle çevrimiçi `expo install --check` | Başarılı: `Dependencies are up to date` |
| Kullanıcı izniyle güncel production audit | Ham rapor 22 high / 0 critical; dört bilinen kök danışman. Kapsam/bütünlük denetimi geçti; yalnız mevcut yayın engeli exit 1 üretti |
| Ayrı engel kaldırma değişikliğinin yakın regresyonları | 79/79 geçti; bilinmeyen danışman, kritik bulgu, eksik/değişmiş yama ve süre sonu hâlâ reddedilir |
| Ayrı engel kaldırma değişikliğinin audit ve kaynak testleri | Gerçek production audit başarılı; 193/193 test geçti. Azalan üç test yalnız kaldırılan koşulsuz engelin politika testleridir |
| Ayrı engel kaldırma değişikliğinin tam `npm run verify:release` kontrolü | Audit, üç TypeScript kontrolü, 193 test, çevrimiçi Expo kontrolü ve 674 modüllük Android/Hermes export başarılı |
| Expo Android export ve source map | 674 Metro modülüyle Hermes çıktısı başarılı; source map'te Forge yok |

Bozuk DigestInfo'lar test özel anahtarıyla imzalanır. Testler ayrıştırıcının ret davranışını gösterir; özel anahtar olmadan saldırı gösterimi değildir. Uygulama/EAS imzalama anahtarları kullanılmaz ve üretilen test özel anahtarları diske yazılmaz. Upstream test kaynakları resmî v1.4.0 etiketinden alınmış ve Git blob özetleriyle kontrol edilmiştir; bu tablo tam upstream test paketi iddiası değildir.

## Eksik yayın kanıtı ve istisnalar

İlk çevrimiçi kontrol girişimleri, özel proje meta verisi paylaşımı için açık izin bulunmadığı gerekçesiyle otomatik onay incelemesinde reddedilmişti. Kullanıcı 11 Ekim'de npm/Expo paylaşımına açık izin verdi. Sonraki çevrimiçi Expo SDK kontrolü başarılıdır. Güncel `npm audit --omit=dev --json`, 22 high / 0 critical ve yalnız dört bilinen kök danışman (node-forge, braces ve iki image-size danışmanı) döndürdü; yeni danışman yoktur. Gerçek `audit:production` rapor/kapsam ve iki yama denetimini geçti; yalnız korunmuş node-forge yayın engeli nedeniyle exit 1 ile durdu. Ham rapor sıfır açık olarak sunulmaz.

Verilen izin PR iş akışlarındaki aynı çevrimiçi kontrolleri de kapsar. PR #28'in kaynak CI testleri, tipler, Expo ve Android export adımları başarılıdır; yalnız korunan yayın engeli başarısızdır. Engel kaldırma bu sonraki ayrı değişikliktedir. Son HEAD'in tam yayın CI'sı, yeni imzalı Android AAB, cihaz/emülatör smoke testi ve Play kanal doğrulaması henüz tamamlandı sayılmaz. Yerel testlerin geçmesi bu kapıların hepsinin veya mağaza yayınının kanıtı değildir.

Ham audit yayımlanmış 1.4.0 sürümünü değerlendirmeye devam eder; yerel patch onun sürüm etiketini değiştirmez. Audit kodundaki node-forge danışman/graph kapsamı ile Metro/image-size geçici istisnası bu değişiklikte genişletilmemiştir. Geçici istisnaların kaldırılması veya yeniden değerlendirilmesi, yayın engelini kaldıran ayrı incelemenin parçası olmalıdır.

Yerel yama kararı **2 Kasım 2026 gününün sonunda UTC** sona erer. Süre dolunca kurulum ve denetim durur. Tarih otomatik uzatılmaz; upstream durumu ve regresyonlar tekrar incelenmelidir.

## Resmî düzeltmeye ve yayına geçiş

1. Resmî sürüm/danışman/kaynak üzerinden iç eleman sayımının, içerikli NULL'un ve standart dışı uzunlukların gerçekten giderildiğini doğrula; yalnız PR varlığını yeterli sayma.
2. Expo ile uyumlu sürümü kontrollü güncelle ve temiz kurulumda aynı pozitif/negatif RSA vakalarını, upstream regresyonlarını ve Expo akışını çalıştır.
3. Geçici postinstall/manifest ve node-forge audit kapsamını kaldırırken imza regresyonlarını koru; Metro istisnasını ayrıca değerlendir.
4. İzinli güncel audit/Expo ve commit CI kanıtını tamamla. Yayın engelini ayrı değişiklikle kaldır; ardından güncel commit'in tam `verify:release` kontrolü, imzalı Android derlemesi ve smoke testi başarılı olsun.
5. Yeni versionCode ile Türkiye üretim sürümünü hazırla ve Google incelemesine gönder; gönderim ve inceleme sonucu ayrı doğrulansın.

Kaynaklar: [resmî danışman](https://github.com/advisories/GHSA-86w9-cpqp-85rv), [upstream önerisi #1152](https://github.com/digitalbazaar/forge/pull/1152), [eleman sayımı için sabit upstream kaynak](https://github.com/digitalbazaar/forge/blob/ceba34402e329f0365134f23fe19898756527d65/lib/rsa.js), [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), [incelenen Android artefaktının iş akışı](https://github.com/ismailtirtar/stokta/actions/runs/37739716103).
