# SONdpi

Windows için tek anahtarla açılıp kapanan DPI atlatma aracı. GoodbyeDPI'nin yerini alır: kendi motoru vardır, sistem ayarına dokunmaz, bildirim alanında (sistem tepsisi) tek bir anahtar olarak durur. Kullanıcıya son mesajının dilinde yanıt ver (çoğunlukla Türkçe).

## Kullanıcının kararları

- Motor bizim: GoodbyeDPI'den daha iyi olacak. GoodbyeDPI açık kaynaktır (Apache-2.0); fikirleri kullanılır, kod Rust'ta baştan yazılır.
- Terminal programı değil. Bildirim alanında basit bir anahtar: tek tıkla aç, tek tıkla kapat.
- En üst kararlılık ve hız her zaman tercih edilir. Süre gerekçesiyle kapsam küçültme önerme.
- Repo adı SONdpi. README başlığı kullanıcının yazdığı cümledir; değiştirme.
- Repo public (2026-11-13). Commit'ler `uruskan` adı ve GitHub noreply adresiyle atılır; kullanıcının gerçek adı ve e-postası depoya, commit'lere ya da sürüm notlarına yazılmaz. Release çıkarmak ve dışarıdan dosya indirmek yalnızca kullanıcının onayıyla olur; ilk release, inceleme bulguları düzeltilip motor gerçek hatta sınandıktan sonra çıkar.

## Ölçülen gerçekler (Kasım 2026, Turkcell 5G ev interneti, CGNAT, IPv4 + IPv6)

Bunlar tahmin değil, bu hatta yapılan ölçümlerdir. Başka servis sağlayıcılarda farklı olabilir; motor bu yüzden kendini ölçerek ayarlar.

**DPI.**
- Engelli SNI, tek ve sıralı bir ClientHello paketinde görülürse paket sessizce düşürülür (bağlantı zaman aşımına uğrar). HTTP'de Host başlığı için de aynısı.
- ClientHello bölünür ama DPI kandırılamazsa DPI her iki uca RST yollar (yaklaşık 0,2 sn içinde).
- Gerçek ClientHello'dan önce, geçerli sağlama toplamı ve sıra numarası olan, izinli bir SNI taşıyan ve TTL'i sunucuya varmadan biten sahte bir ClientHello DPI'ya ulaşırsa akış serbest kalır. Çalışan yöntem budur.
- Sağlama toplamı bozuk ya da sıra numarası geçmişte olan sahte paketleri DPI yok sayar (işe yaramaz).
- DPI istemciden 6-8 atlama uzakta: sahte paket TTL'i 3, 4, 5 iken hiç çalışmaz, 6-7 kısmen, 8 ve üstü çalışır. Engelli sunucular 18-21 atlama uzakta (SYN-ACK TTL'i 43-46).
- GoodbyeDPI'nin `-5 --frag-by-sni` ayarı (otomatik TTL, bu hatta 10'a denk geliyor) DPI'yı her denemede geçiyor.

**Kayıp SYN.** IPv4 üzerinden Cloudflare adreslerine (ve GitHub'ın Frankfurt adresine) açılan TCP bağlantılarının %4-11'inde SYN'e hiç yanıt gelmiyor. İşletim sisteminin 1. ve 3. saniyedeki yeniden gönderimleri de yanıtsız kalıyor (akışa yapışık). Aynı yerel port bir sonraki denemede çalışıyor (CGNAT dış portu değiştirdiği için), yani her deneme bağımsız. Port 443 ve 8443'te, engelli ve engelsiz sitelerde aynı; IPv6'da ve Google, Akamai, Fastly, CloudFront, Roblox adreslerinde sıfır. Normal bağlantı 60-110 ms'de kuruluyor. GoodbyeDPI ile görülen "bağlantıların %7-8'i zaman aşımı" şikâyetinin tamamı budur; DPI atlatmayla ilgisi yoktur. Çözüm: yanıtsız SYN'i başka bir kaynak porttan yeniden denemek.

**DNS.** Modemin dağıttığı çözümleyici (IPv6'da bağlantı-yerel `fe80::` adresi) engelli alan adları için engel sayfasının adresini döndürüyor ve Windows onu elle girilen IPv4 DNS'in önüne alıyor. Hedefi yeniden yazarak yönlendirme (GoodbyeDPI'nin yaptığı) bağlantı-yerel kaynak adresi yüzünden IPv6'da çalışmıyor. Bu hatta düz UDP/53 ile genel çözümleyicilere sorulan sorular doğru yanıtlanıyor, ama başka sağlayıcılar 53'ü de bozabilir; bu yüzden yanıt DoH ile alınır.

## Mimari

Tek dosya: `sondpi.exe`. Rolü argüman belirler (`src/main.rs`): argümansız tepsi anahtarı, `service` motoru barındıran Windows servisi, `dev` ölçüm için konsol kipi, `install` / `uninstall`.

Motor üç iş yapar ve hiçbiri sistem ayarı değiştirmez; kapatınca her şey eski hâlindedir:

1. **Desync.** Giden TLS ClientHello / HTTP isteğinin ilk paketini yakalar, önüne TTL'i sınırlı sahte istek koyar ve gerçeğini bölerek yollar.
2. **Yeniden arama.** Yanıtsız kalan SYN'i yedek bir kaynak porttan yeniden yollar; kazanan yol için akışın bütün paketlerinde port çevirisi yapar. Uygulama hiçbir şey fark etmez (ISN ve seçenekler aynıdır).
3. **DNS.** Giden UDP/53 sorgularını yakalar, yanıtı DoH ile alır ve asıl DNS sunucusundan gelmiş gibi içeri enjekte eder. Bağdaştırıcı ayarına dokunmaz; IPv4, IPv6 ve bağlantı-yerel adreslerde çalışır.

| Modül | İş | Sahibi |
|---|---|---|
| `api.rs`, `packet.rs`, `lib.rs`, `main.rs`, `Cargo.toml`, bu dosya | Ortak adlar, paket türü, birleştirme | Lider |
| `tls.rs`, `desync.rs` | ClientHello ayrıştırma/üretme, stratejiler (saf mantık) | Desync işçisi |
| `divert.rs`, `redial.rs`, `engine.rs`, `dev.rs` | WinDivert FFI, yeniden arama, paket döngüleri, geliştirme kipi | Motor işçisi |
| `doh.rs`, `dns.rs` | DoH istemcisi, yerel DNS yanıtlayıcı | DNS işçisi |
| `ipc.rs`, `service.rs`, `tray.rs`, `install.rs` | Kontrol borusu, servis, tepsi anahtarı, kurulum | Kabuk işçisi |

Modüller arası sözleşme, iskelet dosyalardaki `pub` imzalardır. İmzayı genişletebilirsin; var olanı değiştirmen gerekiyorsa raporunda yaz, lider birleştirir.

## Kurallar

- **Bağımlılık.** Tek crate `windows-sys`. Yeni crate ekleme. `Cargo.toml` içinde yalnızca `windows-sys` özellik listesine satır eklenebilir; başka hiçbir satıra dokunma.
- **Dosya sahipliği.** Bir dosyaya aynı anda tek kişi yazar. Sana verilmeyen dosyaya dokunma; ihtiyacın varsa raporunda yaz.
- **Derleme klasörü.** Her işçi kendi `CARGO_TARGET_DIR` klasörünü kullanır (görevinde yazar); varsayılan `target/` lidere aittir.
- **Yönetici hakkı.** İşçiler yönetici gerektiren hiçbir şey çalıştırmaz, servis kurmaz, sürücü yüklemez, sistem ayarı değiştirmez. Motorun gerçek hatta denenmesi lidere aittir ve her deneme kullanıcının onayıyla yapılır.
- **Git.** Yalnızca lider commit atar. İşçiler `git add`, `commit`, `stash`, `reset`, `checkout`, `restore` çalıştırmaz. `git push` ve repo görünürlüğü kullanıcının onayına bağlıdır.
- **unsafe.** Yalnızca FFI sınırında; her blokta neden güvenli olduğunu söyleyen tek satır. Paket mantığı güvenli Rust'tır ve birim testi vardır.
- **Hata.** Motor ağın önünde durur: hiçbir ayrıştırma hatası panik üretmez; anlaşılmayan paket değiştirilmeden geçirilir. Bir iş parçacığı ölürse motor kendini kapatıp sürücü tanıtıcılarını bırakır (yarım çalışan motor, kapalı motordan kötüdür).
- **Dış varlık.** İndirme (WinDivert'in resmî paketi dahil) kullanıcının onayına bağlıdır. `vendor/windivert/` içindekiler GoodbyeDPI 0.2.3rc3 paketinden gelen WinDivert 2.2 dosyalarıdır; lisansı yanındadır.

## Derleme ve test

- `cargo test` saf mantığı sınar; `cargo build --release` exe'yi üretir. Uyarısız derlenmeli.
- Gerçek hat ölçümleri `tools/` altındaki Node betikleriyle yapılır (yalnızca geliştirme için): `probe.js` (TLS el sıkışması, gerçek IP'ye sabitlenmiş), `synprobe.js` (yalnızca TCP bağlantısı; kayıp SYN oranı), `tuple.js` (aynı kaynak portu yeniden deneme).
- Motoru denemek yönetici hakkı ister. Açık kalan, istek dinleyen yönetici yardımcısı kurma: bu yol güvenliği zayıflattığı için reddedildi (2026-11-13). Her deneme, ne yapacağı önceden kullanıcıya söylenen ve kullanıcının onayladığı tek seferlik bir çalıştırmadır: motoru belli bir süre açar, ölçer, kapatır ve çıkar.
- Bu makinede kurulu `GoodbyeDPI` servisi motorla aynı anda çalışmamalı; deneme sırasında durdurulur, deneme bitince yeniden başlatılır (kullanıcının interneti ona bağlı).
- Akıcılığı ve gerçek uygulamaları (Discord uygulaması, sesli kanal) lider ölçemez; kullanıcıya bırakılır ve raporda ayrı yazılır.
