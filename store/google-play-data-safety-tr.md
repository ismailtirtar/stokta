# Stokta — Google Play Veri Güvenliği taslağı

Bu belge, mevcut 1.3.0 kaynak koduna göre Play Console formunu doldurmak için hazırlanmıştır. Son gönderimde Play Console sorularının güncel metniyle karşılaştırılmalıdır.

## Genel yanıtlar

- Uygulama kullanıcı verisi topluyor veya paylaşıyor mu? `Evet — topluyor`
- Veriler üçüncü taraflarla paylaşılıyor mu? `Hayır`
- Tüm veriler aktarım sırasında şifreleniyor mu? `Evet — HTTPS/TLS`
- Kullanıcı veri silme talebinde bulunabilir mi? `Evet`
- Uygulama hesap oluşturmayı destekliyor mu? `Evet — kullanıcı kendi işletmesini ve ilk yönetici hesabını, işletme yöneticisi çalışan hesaplarını oluşturur`
- Uygulama içinde hesap silme var mı? `Evet — Hesabım > Hesabımı sil`
- Uygulama dışında hesap silme kaynağı var mı? `Evet — yayımlanacak gizlilik/hesap silme web sayfası`

Supabase, geliştirici adına altyapı hizmeti veren veri işleyen/hizmet sağlayıcıdır. Hizmet sağlayıcıya aktarım, Google Play tanımına göre “paylaşım” olarak işaretlenmez; veri yine de “toplanan” olarak beyan edilir.

## Beyan edilecek veri türleri

### Kişisel bilgiler > Ad

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Uygulama işlevselliği`, `Hesap yönetimi`
- Açıklama: Kullanıcı kendi işletmesini kaydederken adını girer; yönetici çalışan hesabı oluştururken çalışanın görünen adını girer. İşlem geçmişinde işlemi yapan kişi gösterilir.

### Kişisel bilgiler > Kullanıcı kimlikleri

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Kullanıcı adı ve Supabase tarafından üretilen hesap kimliği kimlik doğrulama/yetkilendirme için kullanılır. Gerçek e-posta adresi toplanmaz; dahili `@stokta.invalid` adresi kullanıcı adından otomatik üretilir.

### Uygulama etkinliği > Kullanıcı tarafından oluşturulan diğer içerikler

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Uygulama kullanıldığında gerekli`
- Amaç: `Uygulama işlevselliği`
- Açıklama: Ürün adı, ürün kodu, kategori, birim ve isteğe bağlı stok hareketi notları ortak stok işlevi için saklanır.

### Uygulama etkinliği > Diğer işlemler

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Uygulama kullanıldığında gerekli`
- Amaç: `Uygulama işlevselliği`
- Açıklama: Stok ekleme/düşme türü, miktarı, önceki/yeni stok ve işlem zamanı ekip senkronizasyonu ve geçmiş için tutulur.

### Cihaz veya diğer kimlikler

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Yalnızca yeni işletme kaydı sırasında`
- Amaç: `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Toplu sahte kayıtları sınırlandırmak için ağ adresinin tek yönlü özeti saatlik hız sınırında kullanılır. Ham ağ adresi bu tabloda saklanmaz; süresi geçmiş özetler temizlenir.

## Toplanmayan veri türleri

Konum, gerçek e-posta, telefon, adres, finans, sağlık, mesajlar, fotoğraf/video/ses, dosya, takvim, kişiler, web geçmişi, yüklü uygulamalar, reklam kimliği, analiz, çökme kaydı ve tanılama verisi uygulama kodu tarafından toplanmaz. Reklam veya analiz SDK'sı yoktur.

## Silme davranışı

- Çalışan silme: Auth hesabı ve profilindeki ad/kullanıcı adı kaldırılır. Ortak stok kayıt bütünlüğü için geçmiş hareketler “Silinmiş kullanıcı” olarak anonim kalır.
- İşletme yöneticisi silme: Yalnızca bağlı işletmenin ürünleri, stok hareketleri, yönetici profili ve çalışan hesapları kalıcı olarak silinir; diğer kiracı işletmeler etkilenmez.

Google Play, üçüncü taraf SDK'ların işlediği veriler dahil tüm geliştirici beyanlarının doğru olmasını ister. Kaynak: [Veri Güvenliği formu](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en).
