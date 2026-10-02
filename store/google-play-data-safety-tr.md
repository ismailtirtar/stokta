# Stokdaş — Google Play Veri Güvenliği beyanı

Bu belge, uygulama veri akışını Play Console Veri Güvenliği formuyla karşılaştırmak için çalışma taslağıdır. Google Play abonelik yaşam döngüsü değişikliği canlıya alınmadan ve her yeni sürüm yayımlanmadan önce gerçek Play Console beyanı, dağıtılan sunucu kodu ve kullanılan SDK’larla karşılaştırılmalıdır.

2 Ekim 2026 canlı Console kontrolünde 30 Ağustos beyanında satın alma geçmişinin eksik olduğu ve genel paylaşım yanıtının “Hayır” kaldığı görüldü. Satın alma geçmişi ve kullanıcı kimlikleri aşağıdaki toplama/paylaşma ayrıntılarıyla düzeltildi; son **Kaydet** işleminden sonra “Değişiklik kaydedildi. Yayınlama özeti sayfasından incelemeye gönderin.” mesajı doğrulandı.
[Yayınlama özetinde](https://play.google.com/console/u/0/developers/7937586806527687849/app/4973790618727457871/publishing) “Veri Güvenliği anketi dolduruldu” satırı **Henüz incelemeye gönderilmeyen değişiklikler** altında doğrulandı. Dört bekleyen değişiklik vardı; diğer üçü önceki açık test ayarlarıdır. Kaydetme sonrasında otomatik ön kontroller gösterildi; form incelemeye gönderilmedi veya onaylanmadı.

## Genel yanıtlar

- Uygulama kullanıcı verisi topluyor veya paylaşıyor mu? `Evet — topluyor ve paylaşıyor`
- Veriler üçüncü taraflarla paylaşılıyor mu? `Evet — Google Play akışında satın alma geçmişi ve kullanıcı kimlikleri`
- Tüm veriler aktarım sırasında şifreleniyor mu? `Evet — HTTPS/TLS`
- Kullanıcı veri silme talebinde bulunabilir mi? `Evet`
- Uygulama hesap oluşturmayı destekliyor mu? `Evet — kullanıcı kendi işletmesini ve ilk yönetici hesabını, işletme yöneticisi çalışan hesaplarını oluşturur`
- Uygulama içinde hesap silme var mı? `Evet — Hesabım > Hesabımı sil`
- Uygulama dışında hesap silme kaynağı var mı? `Evet — https://stokdas.tirtarhan.chatgpt.site/gizlilik#hesap-silme`

Supabase, Stokdaş’ın sunucu altyapısını sağlar. Satın alma belirteci sunucudan Google Play Publisher API’sine doğrulama için iletilir; kullanıcı ve işletme kimliklerinin SHA-256 özetleri Google Play Billing satın alma isteğinde Google Play’e gönderilir. Bu aktarımlar satın alma geçmişi ve kullanıcı kimlikleri için paylaşım olarak beyan edildi; kimlikleri özetlemek bu verilerin ilgili hesaba bağlanmasını ortadan kaldırmaz.

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
- Paylaşılan: `Evet — Google Play satın alma isteğindeki kullanıcı/işletme kimliği özetleri`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Toplama amacı: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Paylaşma amacı: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Kullanıcı adı ve Supabase tarafından üretilen hesap kimliği kimlik doğrulama/yetkilendirme için gerekir. Satın alma sırasında kullanıcı ve işletme kimliklerinin SHA-256 özetleri, Google Play’e `obfuscatedAccountId` ve `obfuscatedProfileId` olarak iletilir; sunucu aboneliğin aynı kullanıcı/işletmeye ait olduğunu bu özetlerle doğrular. Kimliklerin toplanması zorunludur; Google Play ile paylaşım satın alma akışında gerçekleşir. Eski hesapların dahili `@stokta.invalid` kimlikleri geriye dönük uyumluluk için korunur.

### E-posta adresi

- Toplanıyor: `Evet`
- Paylaşılıyor: `Hayır`
- Geçici işleme: `Hayır`
- Zorunlu: `Evet`
- Amaç: `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Kayıt sırasında sağlanan e-posta adresi yeni işletme veya çalışan hesabını etkinleştirmek için doğrulanır; etkin hesapta kurtarma e-postası olarak güvenlik bildirimleri ve şifre kurtarma için kullanılır.

### Finansal bilgiler > Satın alma geçmişi

- Toplanan: `Evet`
- Paylaşılan: `Evet — Google Play doğrulama akışı`
- Geçici işleme: `Hayır`
- Zorunlu: `Hayır — isteğe bağlı`. Yeni işletme 14 günlük uygulama içi denemeyi satın alma yapmadan kullanabilir; çalışan kendi adına satın alma yapmadan işletmesine erişebilir. Kullanıcı satın alma veya geri yüklemeyi seçtiğinde bu işlem için satın alma kaydı gereklidir.
- Toplama amacı: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Paylaşma amacı: `Uygulama işlevselliği`, `Hesap yönetimi`, `Dolandırıcılığı önleme, güvenlik ve uygunluk`
- Açıklama: Ürün/plan, abonelik durumu ve dönemi, yenileme/iptal/iade ve doğrulama zamanı saklanır. Satın alma belirteci sunucunun özel alanında şifreli olarak ve ayrıca özetiyle; sipariş referansı yalnız geri döndürülemez özetiyle saklanır. İade edilmiş siparişlerin yeniden hak açmasını önleyen belirteç/sipariş özetleri ve doğrulama kilidi teknik kayıtları otomatik süre sonu olmadan kalabilir. Web banka havalesi bildiriminde gönderen adı, tutar, tarih, isteğe bağlı banka işlem referansı/not ve inceleme kararı saklanır. Gönderen adı ve hesap ilişkileri kişisel bilgi alanlarıyla da karşılaştırılmalıdır. Kart ve ödeme yöntemi bilgisi Stokdaş’a aktarılmaz.

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

Konum, telefon, adres, kart, ödeme hesabı ve ödeme yöntemi bilgisi, sağlık, mesajlar, fotoğraf/video/ses, dosya, takvim, kişiler, web geçmişi, yüklü uygulamalar, reklam kimliği, analiz, çökme kaydı ve tanılama verisi uygulama kodu tarafından toplanmaz. Google Play abonelik geçmişi yukarıda ayrı beyan edilir. Reklam veya analiz SDK'sı yoktur.

## Silme davranışı

- Ödeme kaydı varsa: Mevcut şifreyle doğrulanmış silme talebi, hesap/işletme kimliği, kapsam, ödeme inceleme durumu ve zamanla özel tabloda kaydedilir. Sahibi durumunu uygulamadan görür; yalnız canlı TOTP AAL2 oturumlu platform operatörü talebi inceleniyor olarak işaretleyebilir. Bu işlem ödeme kaydını silmez ve silme tamamlandı demez. Bekleyen ödeme iddiası ve incelenmiş kayıtlar korunur; nihai saklama/minimizasyon ve kişisel veri silme işlemi ayrıca tamamlanmalıdır.
- Geçici Auth hatası: Veritabanı temizliği atomiktir; Auth temizliği aynı işlemde yazılan kalıcı iş kuyruğundan servis rolüne özel çalışanla yeniden denenir. İleride yeniden denenecek işler de tamamlanma kontrolünde sayılır. Mobil istemci kişisel veriler silindi/giriş temizliği sırada ayrımını gösterir ve yerel oturumu kapatır.
- Uygulama içi silme onayı: Kullanıcı doğrulama metnini ve mevcut şifresini girer. Geçici şifreyle açılmış hesap, silmeden önce zorunlu şifre değişikliğini tamamlamalıdır.
- Çalışan silme: Auth hesabı, kurtarma e-postası ve profilindeki ad/kullanıcı adı kaldırılır. Geçmiş stok hareketlerinde ve PDF aktarım kayıtlarında kullanıcı kimliği boşaltılır ve görünen ad “Silinmiş kullanıcı” olur; çalışanın oluşturduğu ürünlerin sahipliği etkin işletme yöneticisine aktarılır.
- Çalışanın bildirim geçmişi: Silinen çalışan bildiren ise bildiren kimliği boşaltılır, adı “Silinmiş kullanıcı” olur ve yazdığı serbest açıklama silinir. Çalışan bildirilen kullanıcı ise hedef kimliği boşaltılır, hedef etiketi ile kullanıcı kanıt kopyası “Silinmiş kullanıcı” olur. Çalışan moderatör ise çözen kimliği boşaltılır, görünen adı “Silinmiş kullanıcı” olur ve moderasyon notu silinir. Bildirimin neden, durum ve işlem kaydı işletme silinene kadar korunur.
- İçerik bildirimi saklama: Bildirim nedeni, açıklaması, hedef etiketi, sunucunun ürettiği içerik kanıt kopyası, durum ve moderasyon işlemi ilgili işletme çalışma alanı var olduğu sürece saklanır. Hedef ürün veya hareket kaldırılmış olsa bile kanıt kopyası bildirim geçmişinde kalır.
- İşletme yöneticisi silme: Bağlı işletmenin ürünleri, stok hareketleri, kullanıcı hesapları, içerik bildirimleri, bildirim açıklamaları ve sunucu tarafından üretilen kanıt kopyaları kalıcı olarak silinir; diğer kiracı işletmeler etkilenmez.
- Google Play aboneliği: İlgili abonelik kaydı silindiğinde şifreli satın alma belirteci kasası da silinir; Google Play aboneliğinin otomatik yenilemesi ayrıca Play üzerinden iptal edilmelidir. İade edilen siparişin yeniden erişim açmasını önleyen belirteç/sipariş özeti ile doğrulama kilidi teknik kayıtlarına otomatik süre sonu uygulanmaz ve hesap/işletme silindikten sonra kalabilir.
- Güvenlik denetim olayları: Olay türü, dahili kayıt kimlikleri, hedef türü, neden/işlem ve zaman gibi teknik güvenlik kayıtları kullanıcı veya işletme silindikten sonra da saklanabilir ve otomatik süre sonuna tabi değildir. Bunlar ham kullanıcı içeriği, bildirim kanıt kopyası, bildiren açıklaması veya moderasyon notu içermez. Silinen kullanıcı/işletmeye bağlı doğrudan kimlik ilişkileri boşaltılır; kullanıcı adı ve kullanıcı hedef kimliği ilgili denetim olayından çıkarılır. Bu kayıtlara yalnızca sunucu hizmet rolü erişebilir.

Google Play, üçüncü taraf SDK'ların işlediği veriler dahil tüm geliştirici beyanlarının doğru olmasını ister. Kaynak: [Veri Güvenliği formu](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en).

## Açık test yayın kapısı

Ödeme kaydıyla ilişkili talebin kalıcı kayda ve yetkili inceleme kuyruğuna alınması, silme akışının tamamlandığını göstermez. Bu kullanıcılar için nihai veri silme/minimizasyon, tutulacak muhasebe kayıtlarının gerekçesi ve süresi, incelemenin sonuçlandırılması ve destek SLA'sı doğrulanmadan bu yol tamamlandı olarak yayımlanamaz. Süre/yasal yükümlülük uydurulmaz; gerçek işletme ihtiyacı ve uygulanabilir yükümlülük ayrıca kararlaştırılmalıdır. Dağıtımda Auth temizlik zamanlayıcısı ve hata izleme çalıştırılıp doğrulanmalıdır.

2 Ekim düzeltmesi Console’da kaydedilip yayınlama kuyruğuna eklendi; **incelemeye gönderme ve Google Play onayı hâlâ açık kapıdır**. Ön kontroller tamamlandığında kaydedilmiş satın alma geçmişi/kullanıcı kimliği yanıtları yeniden okunmalı, yeni sürüm ve public gizlilik politikasıyla karşılaştırılmalı; inceleme ve yayımlanmış beyan ayrıca doğrulanmalıdır. Bu dosya Console beyanını kendiliğinden değiştirmez. Kart/ödeme yöntemi bilgisi Stokdaş’a gelmediği için onu abonelik geçmişiyle karıştırmayın.
