# Platform operatörü TOTP MFA ve kurtarma prosedürü

Bu prosedür yalnızca `profiles.is_platform_operator = true` olan Stokdaş hesabı içindir. Normal işletme yöneticileri ve çalışanlar mevcut AAL1 oturum akışını kullanmaya devam eder.

## Zorunlu canlı ayarlar

Stokdaş Supabase projesinin Auth yapılandırmasında aşağıdaki değerler açık olmalıdır:

- `password_hibp_enabled = true`
- `mfa_totp_enroll_enabled = true`
- `mfa_totp_verify_enabled = true`

Yerel Supabase ortamı için TOTP kayıt ve doğrulama bayrakları `supabase/config.toml` içinde de açık tutulur. Sızdırılmış parola koruması ise barındırılan projenin Auth ayarıdır; kaynak deposundaki yerel yapılandırma canlı `password_hibp_enabled` değerini kanıtlamaz.

Yönetim API'si kullanılırsa önce mevcut Auth yapılandırması okunmalı, sonra yalnızca bu üç alan değiştirilmelidir. Proje referansı veya erişim belirteci kaynak koda, issue yorumuna ya da destek kaydına yazılmamalıdır.

## İlk kurulum

1. Platform operatörü kullanıcı adı ve şifresiyle giriş yapar.
2. Uygulama, platform ekranlarını açmadan önce TOTP kurulumunu zorunlu tutar.
3. Kurulum anahtarı bir doğrulayıcı uygulamaya eklenir.
4. Kayıp cihaz için aynı anahtar, ana telefondan ayrı ve şifreli bir parola yöneticisine veya ayrı bir doğrulayıcı cihaza kaydedilir.
5. Altı haneli kod doğrulanır. Platform işlemleri ancak yeni erişim belirtecindeki `aal = aal2` doğrulandıktan sonra açılır.

Kurulum anahtarı ekran görüntüsü, düz metin notu, e-posta veya mesajlaşma uygulamasında saklanmamalıdır.

## Kurtarma kodu durumu

Projede sabitlenen Supabase istemci sürümü TOTP için tek kullanımlık kurtarma kodu üretmez. Bu nedenle kurtarma yöntemi kurulum anahtarının ayrı ve şifreli yedeğidir. Uygulama veya destek ekibi kullanıcıya sahte “kurtarma kodları” üretmemelidir.

## Cihaz kaybolduğunda

### Güvenli yedek varsa

1. Platform operatörü normal şifresiyle giriş yapar.
2. Yedek doğrulayıcıdaki kodla AAL2 doğrulamasını tamamlar.
3. Güvenli bir yönetim ortamında kayıp cihazın faktörü kaldırılır ve yeni bir yedek hazırlanır.
4. Oturum yenilenir; erişim belirtecinin tekrar `aal2` olduğu doğrulanır.

### Tüm TOTP erişimi kaybolduysa

Bu işlem mobil uygulamaya açık bir “MFA sıfırla” uç noktası eklenerek yapılmaz.

1. Hesap sahibinin kimliği ve olay, daha önce kayıtlı çevrimdışı işletme kayıtlarıyla iki kişi kuralı uygulanarak doğrulanır.
2. Yetkili kişi yalnızca güvenli sunucu ortamında Supabase Admin MFA API ile kullanıcı faktörlerini listeler.
3. Kayıp faktör `auth.admin.mfa.deleteFactor` ile kaldırılır.
4. Daha önce verilmiş erişim belirteçlerinin bayat `aal2` claim'i taşıma ihtimaline karşı tüm kullanıcı oturumları güvenli yönetim ortamından ayrıca iptal edilir ve kullanıcı yeniden girişe zorlanır. Parola, doğrulanmış kurtarma e-postası akışıyla değiştirilir.
5. İşlem zamanı, uygulayan kişi, hedef kullanıcı ve gerekçe `security_audit_events` kaydına yazılır. TOTP sırrı veya parola kayda eklenmez.
6. Kullanıcı yeniden giriş yapar, yeni TOTP faktörünü kurar ve AAL2 olmadan platform Edge Function/RPC çağrılarının reddedildiği doğrulanır.

## Yayın ve regresyon kontrolü

- Çalışan + AAL1: çalışan stok akışları çalışır; platform ekranı görünmez.
- Normal işletme yöneticisi + AAL1: yönetici stok/çalışan akışları çalışır; platform ekranı görünmez.
- Platform operatörü + AAL1, faktör yok: zorunlu TOTP kurulum ekranı görünür; platform Edge Function/RPC çağrıları reddedilir.
- Platform operatörü + AAL1, faktör var: TOTP doğrulama ekranı görünür; platform çağrıları reddedilir.
- Platform operatörü + AAL2: platform işletme ve moderasyon işlemleri çalışır.
- Süresi dolmuş, sahte veya canlı olmayan oturum: rol ve AAL değeri ne olursa olsun reddedilir.
- Yeni kayıt/parola değişikliğinde sızdırılmış parola: Supabase Auth tarafından reddedilir.
- Faktör kaldırıldıktan sonra: eski JWT hâlâ `aal2` yazsa bile canlı oturumun bağlı TOTP faktörü ve sunucudaki AAL değeri denetlendiği için platform çağrıları reddedilir; istemci oturumu yenileyip AAL1'e düşürür.

Issue, canlı Auth ayarları okunup üç bayrak doğrulanmadan; yeni migration ve `manage-businesses` Edge Function Stokdaş projesine dağıtılmadan; yukarıdaki rol matrisi canlı veya eşdeğer bir test projesinde geçirilmeden kapatılmamalıdır.
