# Stokdaş — Google Play Veri Güvenliği taslağı

Bu belge, mevcut 1.3.2 kaynak koduna göre Play Console formunu doldurmak için hazırlanmıştır. Son gönderimde Play Console sorularının güncel metniyle karşılaştırılmalıdır.

## Genel yanıtlar

- Uygulama kullanıcı verisi topluyor veya paylaşıyor mu? `Evet — topluyor`
- Veriler üçüncü taraflarla paylaşılıyor mu? `Hayır`
- Tüm veriler aktarım sırasında şifreleniyor mu? `Evet — HTTPS/TLS`
- Kullanıcı veri silme talebinde bulunabilir mi? `Evet`
- Uygulama hesap oluşturmayı destekliyor mu? `Evet — kullanıcı kendi işletmesini ve ilk yönetici hesabını, işletme yöneticisi çalışan hesaplarını oluşturur`
- Uygulama içinde hesap silme var mı? `Evet — Hesabım > Hesabımı sil`
- Uygulama dışında hesap silme kaynağı var mı? `Evet — https://stokdas.tirtarhan.chatgpt.site/gizlilik#hesap-silme`

Supabase, geliştirici adına altyapı hizmeti veren veri işleyen/hizmet sağlayıcıdır. Hizmet sağlayıcıya aktarım, Google Play tanımına göre “paylaşım” olarak işaretlenmez; veri yine de “toplanan” olarak beyan edilir.

## Beyan edilecek veri türleri

### Kişisel bilgiler > Ad

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Uygulama işlevselliği`, `Hesap yönetimi`
- Açıklama: Kullanıcı kendi işletmesini kaydederken adını girer; yönetici çalışan hesabı oluştururken çalışanın görünen adını girer. İşlem geçmişinde işlemi yapan kişi gösterilir.

### Kişisel bilgiler > Diğer kişisel bilgiler

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Uygulama işlevselliği`, `Hesap yönetimi`
- Açıklama: İşletme adı ve kullanıcının işletmedeki rolü, ortak stok alanını ve yetkileri yönetmek için saklanır.

### Kişisel bilgiler > Kullanıcı kimlikleri

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Kullanıcı adı ve Supabase tarafından üretilen hesap kimliği kimlik doğrulama/yetkilendirme için kullanılır. Eski hesapların dahili `@stokta.invalid` kimlikleri geriye dönük uyumluluk için korunur.

### E-posta adresi

- Toplanıyor: `Evet`
- Paylaşılıyor: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Kayıt sırasında sağlanan e-posta adresi yeni işletme veya çalışan hesabını etkinleştirmek için doğrulanır; etkin hesapta kurtarma e-postası olarak güvenlik bildirimleri ve şifre kurtarma için kullanılır.

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
- Zorunlu: `Hesap ve güvenlik işlemleri sırasında gerekli`
- Amaç: `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: İstek sırasında Supabase/API altyapısına ulaşan ağ adresi ve bundan türetilen tek yönlü özet, hesap güvenliği ve kötüye kullanımı önleme amacıyla hizmet günlüklerinde ve güvenlik kayıtlarında işlenebilir. Ham ağ adresi uygulamanın hız sınırı tablosunda saklanmaz.

## Toplanmayan veri türleri

Konum, telefon, adres, finans, sağlık, mesajlar, fotoğraf/video/ses, dosya, takvim, kişiler, web geçmişi, yüklü uygulamalar, reklam kimliği, analiz, çökme kaydı ve tanılama verisi uygulama kodu tarafından toplanmaz. Reklam veya analiz SDK'sı yoktur.

## Silme davranışı

- Uygulama içi silme onayı: Kullanıcı doğrulama metnini ve mevcut şifresini girer. Geçici şifreyle açılmış hesap, silmeden önce zorunlu şifre değişikliğini tamamlamalıdır.
- Çalışan silme: Auth hesabı, kurtarma e-postası ve profilindeki ad/kullanıcı adı kaldırılır. Ortak stok kayıt bütünlüğü için geçmiş hareketler “Silinmiş kullanıcı” olarak anonim kalır.
- İşletme yöneticisi silme: Yalnızca bağlı işletmenin ürünleri, stok hareketleri, yönetici profili ve çalışan hesapları kalıcı olarak silinir; diğer kiracı işletmeler etkilenmez.
- Güvenlik kayıtları: Güvenlik ve kötüye kullanım önleme kayıtları; olay incelemesi, hizmet güvenliği veya yasal yükümlülükler için gerekli olduğu sınırlı süre boyunca erişimi kısıtlı olarak tutulabilir. Play formu gönderilmeden önce canlı sistemdeki saklama süresi ve otomatik temizleme davranışı doğrulanmalıdır.

Google Play, üçüncü taraf SDK'ların işlediği veriler dahil tüm geliştirici beyanlarının doğru olmasını ister. Kaynak: [Veri Güvenliği formu](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en).
