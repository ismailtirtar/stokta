# Stokdaş — Android

Birden fazla işletmenin birbirinden tamamen ayrılmış bulut stoklarıyla çalışabildiği, kiralanabilir Expo/React Native uygulamasıdır. Bu paket, Frankfurt bölgesindeki Stokdaş Supabase altyapısına bağlıdır.

## Hazır özellikler

- Kullanıcı adı ve şifre ile güvenli oturum
- İşletme bazlı veri izolasyonu ve ayrı yönetici/çalışan hesapları
- Uygulama içinden yeni işletme ve ilk yönetici hesabı oluşturma
- Yeni işletmeler için 14 günlük deneme ve sunucu taraflı kayıt hız sınırı
- Platform yöneticisinin mevcut işletmelerin abonelik/askıya alma durumunu ve sınırlarını yönetebilmesi; yeni işletmeler yalnız self-servis kayıt akışından açılır
- Deneme, aktif, ödeme bekleyen, askıda ve iptal abonelik durumları
- İşletme başına kullanıcı ve ürün limitleri
- Yalnızca yöneticinin çalışan hesabı ve ürün oluşturabilmesi
- Tüm çalışanların ortak stok ekleme ve stoktan düşme işlemleri
- Negatif stoku engelleyen atomik veritabanı işlemleri
- Kritik stok ve tükenen ürün göstergeleri
- İşlemi yapan kullanıcının kaydı ve son hareketler
- Realtime yayınına alınmış ürün ve stok hareketlerinde gerçek zamanlı ekip senkronizasyonu; yeniden bağlanma sonrası sunucu yenilemesi
- Android telefonlara uygun mobil arayüz
- Google Play için API 36 / AAB üretim yapılandırması ve mağaza görselleri
- Uygulama içi gizlilik politikası ve kalıcı hesap silme

## Mevcut bulut bağlantısı

- Supabase project ref: `wewqrnpwqvnjusehxxtz`
- URL: `https://wewqrnpwqvnjusehxxtz.supabase.co`
- Bölge: Frankfurt (`eu-central-1`)

Yerel geliştirmede `.env`, EAS Build'de proje ortam değişkenleri kullanılır. Uygulamaya yalnızca herkese açık publishable key verilir; `service_role` anahtarı pakette ve kaynak depoda bulunmaz.

## İşletme kiralama akışı

1. Yeni müşteri giriş ekranındaki `Yeni işletme` sekmesinden işletme adını ve ilk yönetici hesabını oluşturur.
2. İşletme 14 günlük denemeyle açılır ve ilk kullanıcı işletme yöneticisi olur.
3. İşletme yöneticisi sağ üstteki `+ Çalışan` düğmesiyle kendi ekip hesaplarını oluşturur.
4. Çalışanlar yalnızca bağlı oldukları işletmenin ürünlerini ve hareketlerini görür.
5. Platform yöneticisi uygulamadaki `İşletmeler` ekranından kiralama süresini etkinleştirebilir, limitleri değiştirebilir veya işletmeyi askıya alabilir.

İşletme yöneticileri kendi işletmelerini uygulamadan kaydedebilir. Yeni işletme ve çalışan hesapları doğrulanmış kurtarma e-postasıyla etkinleştirilir; kullanıcılar e-posta koduyla hesaplarını doğrulayabilir ve şifrelerini yenileyebilir. Eski hesaplarda kullanılan `<kullanici_adi>@stokta.invalid` dahili kimlikleri geriye dönük uyumluluk için korunur ve arayüzde gösterilmez.

## Yerel çalıştırma

```bash
npm ci
npx expo start
```

Expo Go yüklü Android telefonla ekrandaki QR kod okutularak test edilebilir.

## Doğrulama ve Android çıktısı

```bash
npm run typecheck
npm run export:android
npm run build:play
```

Kurulabilir APK için EAS hesabıyla:

```bash
npx eas-cli login
npm run build:apk
```

## Arka uç kaynakları

- `supabase/schema.sql` ve `supabase/migrations/`: tablolar, RLS, yetkiler, atomik/idempotent stok RPC işlevleri, imleçli listeleme ve ürün/hareket tablolarının Realtime yayını.
- `supabase/config.toml`: herkese açık doğrulama uçları ile oturum gerektiren yönetim uçlarının JWT geçidi yapılandırması.
- `supabase/migrations/20260822125630_multitenant_saas.sql`: çok kiracılı işletme, abonelik ve veri izolasyonu geçişi.
- `supabase/functions/bootstrap-admin/index.ts`: yalnızca boş bir kurulumda ilk platform yöneticisini oluşturma.
- `supabase/functions/create-coworker/index.ts`: yalnızca yönetici tarafından çalışan hesabı oluşturma.
- `supabase/functions/manage-businesses/index.ts`: platform operatörünün mevcut işletmelerin abonelik, askıya alma ve sınır durumunu iyimser eşzamanlılıkla yönetmesi. Yeni kiracı oluşturma isteği `410` döner; kayıt self-servistir.
- `supabase/functions/register-business/index.ts`: yeni müşterinin uygulama içinden kendi işletmesini ve ilk yönetici hesabını oluşturması.
- `supabase/functions/delete-account/index.ts`: çalışanın kendi hesabını, yöneticinin yalnızca kendi işletmesini güvenli biçimde silmesi.
- `supabase/functions/verify-play-subscription/index.ts`: satın alma niyeti, sahiplik ve Google Play abonelik doğrulaması; ACK otoritesi sunucudur.
- `supabase/functions/google-play-rtdn/index.ts`: Google Play gerçek zamanlı geliştirici bildirimlerini doğrulayıp dayanıklı kuyruğa alma.
- `supabase/functions/google-play-reconcile/index.ts`: RTDN tekrarlarını, yenileme/iptal/geri ödeme durumlarını ve süreli şifreli belirteç saklamasını uzlaştırma.
- `supabase/migrations/20260911123000_google_play_subscription_lifecycle_v2.sql`: satın alma niyeti, sahiplik zinciri, tek ACK akışı, RTDN/reconcile işleri ve sınırlı saklama yaşam döngüsü.
- `store/`: Google Play mağaza metni, Veri Güvenliği taslağı, gizlilik sayfası ve yayın kontrol listesi.

## Güvenlik

- Uygulamaya yalnızca Supabase publishable key konur.
- `service_role` anahtarı hiçbir zaman Android uygulamasına eklenmez.
- Ürün yönetimi yalnızca yönetici RPC'leriyle yapılır.
- Stok hareketleri veritabanında satır kilidi altında atomik olarak işlenir.
- Satır düzeyi güvenlik açıktır ve anonim veri erişimi kapalıdır.
- RLS politikaları her ürün ve hareketi kullanıcının `organization_id` değeriyle sınırlar.
- İşletme kodu veya istemci filtresi atlatılsa bile başka kiracının satırları veritabanı tarafından reddedilir.
