# Stokta — Android

Birden fazla işletmenin birbirinden tamamen ayrılmış bulut stoklarıyla çalışabildiği, kiralanabilir Expo/React Native uygulamasıdır. Bu paket, Frankfurt bölgesindeki `Stokta` Supabase projesine bağlıdır.

## Hazır özellikler

- Kullanıcı adı ve şifre ile güvenli oturum
- İşletme bazlı veri izolasyonu ve ayrı yönetici/çalışan hesapları
- Uygulama içinden yeni işletme ve ilk yönetici hesabı oluşturma
- Yeni işletmeler için 14 günlük deneme ve sunucu taraflı kayıt hız sınırı
- Platform yöneticisinin yeni kiracı işletme açabilmesi
- Deneme, aktif, ödeme bekleyen, askıda ve iptal abonelik durumları
- İşletme başına kullanıcı ve ürün limitleri
- Yalnızca yöneticinin çalışan hesabı ve ürün oluşturabilmesi
- Tüm çalışanların ortak stok ekleme ve stoktan düşme işlemleri
- Negatif stoku engelleyen atomik veritabanı işlemleri
- Kritik stok ve tükenen ürün göstergeleri
- İşlemi yapan kullanıcının kaydı ve son hareketler
- Gerçek zamanlı ekip senkronizasyonu
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

İşletme yöneticileri kendi işletmelerini uygulamadan kaydedebilir. Çalışan hesapları güvenlik ve işletme üyeliği kontrolü için yalnızca o işletmenin yöneticisi tarafından oluşturulur. Dahili Auth e-postaları uygulama tarafından `<kullanici_adi>@stokta.invalid` biçiminde üretilir ve arayüzde gösterilmez.

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

- `supabase/schema.sql`: tablolar, RLS, yetkiler, atomik RPC işlevleri ve Realtime yayını.
- `supabase/migrations/20260822125630_multitenant_saas.sql`: çok kiracılı işletme, abonelik ve veri izolasyonu geçişi.
- `supabase/functions/bootstrap-admin/index.ts`: yalnızca boş bir kurulumda ilk platform yöneticisini oluşturma.
- `supabase/functions/create-coworker/index.ts`: yalnızca yönetici tarafından çalışan hesabı oluşturma.
- `supabase/functions/manage-businesses/index.ts`: kiracı işletme oluşturma ve kiralama durumunu yönetme.
- `supabase/functions/register-business/index.ts`: yeni müşterinin uygulama içinden kendi işletmesini ve ilk yönetici hesabını oluşturması.
- `supabase/functions/delete-account/index.ts`: çalışanın kendi hesabını, yöneticinin yalnızca kendi işletmesini güvenli biçimde silmesi.
- `store/`: Google Play mağaza metni, Veri Güvenliği taslağı, gizlilik sayfası ve yayın kontrol listesi.

## Güvenlik

- Uygulamaya yalnızca Supabase publishable key konur.
- `service_role` anahtarı hiçbir zaman Android uygulamasına eklenmez.
- Ürün yönetimi yalnızca yönetici RPC'leriyle yapılır.
- Stok hareketleri veritabanında satır kilidi altında atomik olarak işlenir.
- Satır düzeyi güvenlik açıktır ve anonim veri erişimi kapalıdır.
- RLS politikaları her ürün ve hareketi kullanıcının `organization_id` değeriyle sınırlar.
- İşletme kodu veya istemci filtresi atlatılsa bile başka kiracının satırları veritabanı tarafından reddedilir.
