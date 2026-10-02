# node-forge 1.4.0 yerel güvenlik yaması

GHSA-86w9-cpqp-85rv, RSA PKCS#1 v1.5 doğrulamasının nested `DigestAlgorithm` SEQUENCE içindeki fazladan elemanları kabul etmesidir. node-forge 1.4.0 dış `DigestInfo` uzunluğunu kontrol ederken bu iç yapıyı kontrol etmez. 2 Ekim 2026 kontrolünde npm'in güncel sürümü 1.4.0, resmî danışmanda yamalı sürüm yok ve upstream PR #1152 henüz açık durumdadır. Yerel yama resmî bir node-forge sürümü veya upstream tarafından birleştirilmiş düzeltme olarak sunulmaz.

Yama, iç yapının yalnız OID ve varsa NULL parametresinden oluşmasını zorunlu kılar. `lib/rsa.js` son içeriği upstream önerisinin `ceba34402e329f0365134f23fe19898756527d65` commit'indeki dosyayla bayt bazında aynıdır. Aynı koşul, npm paketinde ayrıca dağıtılan `dist/forge.min.js` ve `dist/forge.all.min.js` dosyalarına da uygulanır; bundle'lar yeniden derlenmez. Sürüm etiketi 1.4.0 olarak kalır, alternatif registry veya fork kullanılmaz.

## Kaynak ve kurulum

`security/node-forge-patch.json` sürümü, registry URL'sini, SHA-512 tarball bütünlüğünü, kurulum/tüketici yollarını, üç kesin metin değişikliğini ve paketin 59 dosyasının SHA-256 özetlerini içerir. Başlangıç envanteri resmî npm tarball'ının SHA-512 bütünlüğü doğrulandıktan ve kurulu paketle bütün dosyaları eşleştirildikten sonra oluşturuldu. Değişen dosyalarda hem özgün hem yamalı SHA-256 bulunur.

`package.json` node-forge sürümünü tam `1.4.0` override'ıyla sabitler. `npm ci` ve `npm install`, `postinstall` içinde `scripts/node-forge-patch.mjs` çalıştırır. Betik önce bütün envanteri ve kilidi kontrol eder, yalnız bilinen özgün dosyaları yamalar ve ikinci çalıştırmada aynı içeriği korur. Bilinmeyen içerik otomatik onarılmaz. Başka dosya değişiklikleri, eksik/ek dosya, sembolik bağlantı, yeni paket kaynağı/sürümü veya tüketici grafiği reddedilir.

Kurulu `@expo/code-signing-certificates` 0.0.6 ve Expo içindeki `@expo/cli` 54.0.27, `createRequire(...).resolve(...)` ile gerçekten çözdükleri node-forge kopyasına kadar denetlenir. Kilitte belirtilmeyen iç içe bir kopya da bu tüketicilerden biri ona çözülürse reddedilir. Her bağımlılık değişikliği bu sabit kapsamın yeniden incelenmesini gerektirir.

## Yayın kontrolü

```bash
npm ci
node scripts/node-forge-patch.mjs --check
npm run verify:release
```

`--check` ve audit kontrolü yamayı uygulamaz veya onarmaz. `npm ci --ignore-scripts` ile kurulmuş özgün paket denetimden geçemez. Audit kapısı, rapor temiz görünse bile yama doğrulamasını ister.

Her doğrulamada ana kaynak ve iki tarayıcı girişinde, 2048 bitlik geçici test anahtarlarıyla hem e=3 hem e=65537 için toplam 60 gerçek RSA doğrulama vakası yürütülür:

- SHA-256 için NULL bulunan ve bulunmayan geçerli DigestInfo; SHA-384/SHA-512 imzaları; mevcut MD5 ayrıştırma uyumluluğu kabul edilir. MD5 testi yeni kriptografi seçimi önerisi değildir.
- Ek nested OCTET STRING, beklenmeyen parametre, yinelenen NULL, ek dış eleman ve yanlış digest reddedilir.
- Regresyon testlerinde özgün paketin üç nested bozuk yapıyı kabul ettiği ayrıca gösterilir; böylece testin yalnız başarılı imzaları kontrol etmediği kanıtlanır.
- Expo'nun gerçek sertifika oluşturma/PEM dönüşümü/doğrulaması, CSR ve SHA-256 imzalama API'leri sınanır. Üretilen imza Node crypto ile bağımsız doğrulanır; değiştirilmiş mesaj reddedilir.

Bu vakalarda bozuk encodings test özel anahtarıyla imzalanır. Testler ayrıştırıcının red davranışını kanıtlar; özel anahtar olmadan üretilmiş yeni bir saldırı gösterimi veya tüm kriptografik uygulamanın ispatı değildir. Uygulama ya da EAS imzalama anahtarları kullanılmaz ve test anahtarları diske yazılmaz.

Ham `npm audit --omit=dev` hâlâ yayımlanmış 1.4.0 sürümünü etkilenmiş gösterir. `audit:production`, yalnız bütünlük ve davranış doğrulaması başarılı olduğunda bu kesin danışmanı ve bilinen Expo dolaylı zincirini yerel olarak azaltılmış sayar. Danışman kimliği/kaynağı/aralığı, kurulum yolları ve zincir ilişkileri denetlenir. Yeni danışman, farklı tüketici, eksik veya döngülü danışman zinciri ve herhangi bir kritik bulgu bu kapsamdan yararlanamaz. Metro/image-size için önceki ayrı geçici istisna genişletilmemiştir.

Yerel node-forge kararı **2 Kasım 2026 gününün sonunda UTC** sona erer. Bu tarihten sonra normal kurulum ve yayın denetimi durur. Süreyi uzatmak otomatik bir işlem değildir; upstream durumu ve regresyonlar tekrar incelenmelidir.

## Resmî düzeltmeye geçiş

1. Yayımlanan sürümün bu danışmanı ve iç eleman sayımı açığını gerçekten giderdiğini resmî danışman, sürüm ve kaynak üzerinden doğrula.
2. Sabit sürümü/Expo bağımlılığını kontrollü güncelle; temiz kurulumda aynı RSA negatif/pozitif vakalarını ve Expo sertifika akışını yeni sürüm üzerinde çalıştır.
3. Geçici `postinstall`, yama manifesti ve audit içindeki koşullu node-forge kapsamını kaldır. İmza regresyonlarını yeni sürüm için koru; Metro istisnasını ayrıca değerlendir.
4. Tam `verify:release` ve güncel commit'in GitHub kontrolleri geçmeden yeni AAB üretme veya Play gönderimi yapma.

Kaynaklar: [resmî danışman](https://github.com/advisories/GHSA-86w9-cpqp-85rv), [upstream önerisi #1152](https://github.com/digitalbazaar/forge/pull/1152), [sabit upstream kaynak dosyası](https://github.com/digitalbazaar/forge/blob/ceba34402e329f0365134f23fe19898756527d65/lib/rsa.js).
