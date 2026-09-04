# Stokdaş — Google Play Veri Güvenliği beyanı

Bu belge, Stokdaş 1.3.3 (12) kaynak kodu ve uygulanan sunucu veri akışına göre Play Console Veri Güvenliği formunda kullanılacak kesin yanıtları içerir.

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
- Amaç: `Uygulama işlevselliği`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Ürün adı, ürün kodu, kategori, birim ve isteğe bağlı stok hareketi notları ortak stok işlevi için saklanır. Kullanıcı bir ürünü, stok hareketi notunu veya hareketi yapan kullanıcıyı bildirdiğinde seçilen neden ve en fazla 1000 karakterlik isteğe bağlı açıklama saklanır. Sunucu hedefi doğrular ve bildirim anındaki kayıtlı ürün alanlarının, stok hareketi notunun veya kullanıcı görünen bilgisinin en fazla 1000 karakterlik kanıt kopyasını üretip moderasyon incelemesi için saklar; kullanıcı bu kopyayı gönderemez veya değiştiremez.

### Uygulama etkinliği > Diğer işlemler

- Toplanan: `Evet`
- Paylaşılan: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Uygulama kullanıldığında gerekli`
- Amaç: `Uygulama işlevselliği`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Stok ekleme/düşme türü, miktarı, önceki/yeni stok ve işlem zamanı ekip senkronizasyonu ve geçmiş için tutulur. Kabul edilen kullanım koşulları sürümü ve kabul zamanı; içerik bildiriminin oluşturulma zamanı, inceleme durumu, inceleyen yöneticinin görünen adı, isteğe bağlı moderasyon notu ve uygulanan işlem; uygulama işlevselliği, hesap yönetimi, güvenlik ve uygunluk amacıyla tutulur.

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
- Çalışan silme: Auth hesabı, kurtarma e-postası ve profilindeki ad/kullanıcı adı kaldırılır. Geçmiş stok hareketlerinde kullanıcı kimliği boşaltılır ve görünen ad “Silinmiş kullanıcı” olur; çalışanın oluşturduğu ürünlerin sahipliği etkin işletme yöneticisine aktarılır.
- Çalışanın bildirim geçmişi: Silinen çalışan bildiren ise bildiren kimliği boşaltılır, adı “Silinmiş kullanıcı” olur ve yazdığı serbest açıklama silinir. Çalışan bildirilen kullanıcı ise hedef kimliği boşaltılır, hedef etiketi ile kullanıcı kanıt kopyası “Silinmiş kullanıcı” olur. Çalışan moderatör ise çözen kimliği boşaltılır, görünen adı “Silinmiş kullanıcı” olur ve moderasyon notu silinir. Bildirimin neden, durum ve işlem kaydı işletme silinene kadar korunur.
- İçerik bildirimi saklama: Bildirim nedeni, açıklaması, hedef etiketi, sunucunun ürettiği içerik kanıt kopyası, durum ve moderasyon işlemi ilgili işletme çalışma alanı var olduğu sürece saklanır. Hedef ürün veya hareket kaldırılmış olsa bile kanıt kopyası bildirim geçmişinde kalır.
- İşletme yöneticisi silme: Bağlı işletmenin ürünleri, stok hareketleri, kullanıcı hesapları, içerik bildirimleri, bildirim açıklamaları ve sunucu tarafından üretilen kanıt kopyaları kalıcı olarak silinir; diğer kiracı işletmeler etkilenmez.
- Güvenlik denetim olayları: Olay türü, dahili kayıt kimlikleri, hedef türü, neden/işlem ve zaman gibi teknik güvenlik kayıtları kullanıcı veya işletme silindikten sonra da saklanabilir ve otomatik süre sonuna tabi değildir. Bunlar ham kullanıcı içeriği, bildirim kanıt kopyası, bildiren açıklaması veya moderasyon notu içermez. Silinen kullanıcı/işletmeye bağlı doğrudan kimlik ilişkileri boşaltılır; kullanıcı hedef kimliği ilgili denetim olayından çıkarılır. Bu kayıtlara yalnızca sunucu hizmet rolü erişebilir.

Google Play, üçüncü taraf SDK'ların işlediği veriler dahil tüm geliştirici beyanlarının doğru olmasını ister. Kaynak: [Veri Güvenliği formu](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en).
