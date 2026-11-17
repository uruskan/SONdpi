# SONdpi

Windows ve macOS için tek anahtarla açılıp kapanan DPI atlatma aracı. GoodbyeDPI'nin yerini alır: kendi motoru vardır, sistem ayarına dokunmaz, bildirim alanında (sistem tepsisi) tek bir anahtar olarak durur. Kullanıcıya son mesajının dilinde yanıt ver (çoğunlukla Türkçe).

## Kullanıcının kararları

- Motor bizim: GoodbyeDPI'den daha iyi olacak. GoodbyeDPI açık kaynaktır (Apache-2.0); fikirleri kullanılır, kod Rust'ta baştan yazılır.
- Terminal programı değil. Bildirim alanında basit bir anahtar: tek tıkla aç, tek tıkla kapat.
- En üst kararlılık ve hız her zaman tercih edilir. Süre gerekçesiyle kapsam küçültme önerme.
- macOS sürümü (2026-11-17): root ve sürücü yok; yerel proxy + sistemin otomatik proxy (PAC) ayarı. Kullanıcı bu yolu seçti (şeffaf pf/root yolu yerine). Menü, Windows tepsisindeki menünün birebir aynısıdır; tek fark Mac'te menünün sol tıkla açılmasıdır (kullanıcı açıkça istedi; başka fark ekleme, menüyü değiştirirken önce `src/tray.rs`'teki `menu_entries`/başlık çizimine bak).
- Repo adı SONdpi. README başlığı yalnızca "SONdpi"dir (kullanıcı uzun, esprili başlığı 2026-11-13'te kaldırttı); "babayla yarışılmaz" rozeti ve maskot kalır. README'nin tonu esprili ama içeriği doğrudur: ölçülmemiş bir şey ölçülmüş gibi yazılmaz, gerçek kişilere söz uydurulmaz.
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

**Motorun ilk gerçek hat sınaması (2026-11-13, `tools/hat-testi.ps1`).** Aynı dakikalarda arka arkaya: engelli adlara TLS, GoodbyeDPI 28/30, SONdpi 40/40; Cloudflare'in üç adresine TCP bağlantısı, GoodbyeDPI 332/360, SONdpi 360/360, yeniden arama kapalıyken SONdpi 335/360. Motor 534 SYN'in 30'unu yanıtsız bulup 30'unu da yedek porttan kurtardı (ortanca 339 ms, biri ikinci yedekle). Modemin IPv4 ve `fe80::` çözümleyicisine sorulan engelli adlar gerçek adreslerle yanıtlandı. 25 MB indirme 16,2 MB/sn (GoodbyeDPI ile 17,1). Motor temiz kapandı, gönderim hatası yok. Sınanmayanlar: uzun süreli kullanım; yükleme (upload) hızı; başka sağlayıcılar.

**Kurulum sınaması (2026-11-13, `tools/kurulum-testi.ps1`).** Kurulum 254 ms; servis LocalSystem, otomatik başlangıç, hata sonrası 5 sn'de yeniden başlama. Servis üzerinden TLS 16/16, bağlantı 160/160. Anahtar kapatılınca engelli adlar 0/8, açılınca 8/8. Anahtarın konumu servis yeniden başlayınca korunuyor (açık da kapalı da). Yetkisiz oturumdan kontrol borusu ve tepsi çalışıyor; simgeye tıklama anahtarı çeviriyor, ipucu durumu gösteriyor. Kaldırma 3,2 sn; servis, klasör, kayıt anahtarı ve süreç kalmıyor. Sınanmayanlar: çift tıkla ilk çalıştırma (uygulamanın kendi UAC istemi), sağ tık menüsündeki kaldırma ve "Windows açılışında başlat", yeniden başlatma sonrası açılış. Not: WinDivert sürücüsü bir kez yüklenince araçlar arasında bellekte kalıyor; yüklü olan, ilk yükleyen aracın klasöründeki dosyadır.

**Devir ve yükseltme (2026-11-13).** Kurulum `GoodbyeDPI` servisini durdurup elle başlatmaya aldı, kaldırma eski hâline döndürdü (çalışıyor, otomatik). Yetkisiz `sondpi.exe install` uygulamanın kendi UAC istemiyle kurulu sürümün üstüne yükseltti (1,8 sn; kullanımdaki exe `.old` olarak kenara alınıyor).

**Maskot (2026-11-13, kullanıcının isteği).** Uygulamada maskot varsayılan olarak görünür: tepsi simgesi maskotun yüzüdür (açık: uyanık, kapalı: uyuyor, sorun: endişeli; köşe rozeti 16 pikselde durumu rengiyle söyler) ve sağ tık menüsünün en üstünde büyük portresi durur. Menüdeki "Maskot simgesi" kapatılırsa ikisi de gider. Çizimler `tools/ikon-uret.ps1` içindedir; `assets/` altındaki `.ico`, `.rc` ve `.res` ondan üretilir ve commit'lenir, `build.rs` `.res` dosyasını exe'ye bağlar. Menü yalnızca %100 ölçekte ve açık temada gözle görüldü.

**Sürüm.** `v0.2.0-windows` (2026-11-18): tepsiyi servis de açar, simge görev çubuğu hazır olana dek yeniden denenir; motor 0.1.1 ile aynı. `SONdpi-0.2.0-windows-x64.zip`; exe sürüm bilgisi `assets/sondpi.rc` elle 0.2.0 yapılıp `rc.exe` ile `.res` yeniden derlendi. Geliştirme bilgisayarında kurulu olan, bu sürümün tepsi değişikliklerini taşıyan bir önceki derlemedir. `v0.2.0-macos` (2026-11-17): ilk macOS ön sürümü, `SONdpi-0.2.0-macos-universal.zip` (SONdpi.app, `OKU-macOS.txt`, lisans); ad-hoc imzalı, notarize değil. `v0.1.1` (maskot, GoodbyeDPI devri, yükseltmede tepsi değişimi) ve `v0.1.0` ön sürüm olarak yayınlandı (2026-11-13): `SONdpi-0.1.0-windows-x64.zip` (exe, WinDivert dosyaları, lisanslar, `OKU.txt`). Geliştirme bilgisayarında bu sürüm kalıcı olarak kurulu ve GoodbyeDPI kaldırıldı; yeni derlemeyi denemek için üstüne `sondpi.exe install` çalıştırılır.

**macOS hattı (2026-11-17, aynı Turkcell hattı, MacBook, yönetici hakkı olmadan; `tools/hat-testi-macos.sh`).**
- Engelli SNI düz gönderilince zaman aşımı; TCP'de bölme ve TTL=1 "disorder" ~0,2-0,3 sn'de RST (Windows'taki gözlemle aynı).
- ClientHello'yu SNI'nin ortasından **iki TLS kaydına** bölmek DPI'yı geçiyor (DPI kayıtları birleştirmiyor); OOB baytı da geçti. Proxy ile engelli adlar 120/120.
- Düz HTTP'de Host değerini bölmek RST alıyor; başlık adını `hoSt:` yazmak geçiyor.
- Kayıp SYN: Cloudflare IPv4'e 120 doğrudan bağlantının 7'si 1 sn'yi aştı ya da kurulamadı; proxy'nin yarışan yeniden aramasıyla 0/120 (15'i kurtarıldı).
- DoH: Quad9 443'te HTTP/1.1'e 505 veriyor; Mac listesi 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4 (SecureTransport, IP sertifikası doğrulanıyor).
- Uçtan uca: sistem proxy'si üzerinden URLSession (Safari'nin yığını) engelli adları açıyor; SIGTERM'de ayar geri yükleniyor; `kill -9` sonrası internet doğrudan sürüyor, yeniden açılışta toparlanıyor. Anahtarı kullanıcı açtı; `networksetup`'ın şifre isteyip istemediği not edilmedi.
- Akamai'nin bazı IPv6 uçları curl'ün varsayılan kullanıcı aracısına `/` için yanıt vermiyor (microsoft.com); proxy ile ilgisi yok.

**Paketli uygulamadan kurulum tuzağı (2026-11-18).** Claude masaüstü uygulaması MSIX paketlidir: ondan ve onun başlattığı süreçlerden yapılan HKCU yazımları pakete özel bir kayıt kopyasına gider, dışarıdaki süreçler (Explorer, servis) onu görmez. 2026-11-13'teki kurulum `Run\SONdpi` girdisini yalnızca o kopyaya yazdığı için 2026-11-16 yeniden başlatmasında tepsi açılmadı. Bu kabuktan HKCU'ya bakan her şey (PowerShell, `reg`, buradan başlatılan tepsi) yanıltıcıdır; gerçek değeri okumak ya da yazmak için komut paket dışında çalıştırılır (ör. `Invoke-CimMethod Win32_Process Create` ile `reg query`/`reg add`), tepsi de aynı yolla başlatılır. Buradan çalıştırılan `sondpi.exe install` sonrasında Run girdisi bu yolla doğrulanır.

**Tepsiyi servis de açar (2026-11-18).** Servis oturum açılışında (`SERVICE_CONTROL_SESSIONCHANGE`, `WTS_SESSION_LOGON`) ve kendi başlangıcında etkin oturumlarda tepsiyi kullanıcı olarak `--autostart` ile başlatır; tepsi kullanıcının Run girdisi yoksa 11 koduyla çıkar, zaten çalışıyorsa 10. Servis, 10 sn içinde kapanan tepsinin çıkış kodunu `service.log`'a yazar. Servis başlangıcı yolu sınandı; oturum açılışı yolu henüz sınanmadı.

## Mimari

Windows: tek dosya `sondpi.exe`. Rolü argüman belirler (`src/main.rs`): argümansız tepsi anahtarı, `service` motoru barındıran Windows servisi, `dev` ölçüm için konsol kipi, `install` / `uninstall`.

Motor üç iş yapar ve hiçbiri sistem ayarı değiştirmez; kapatınca her şey eski hâlindedir:

1. **Desync.** Giden TLS ClientHello / HTTP isteğinin ilk paketini yakalar, önüne TTL'i sınırlı sahte istek koyar ve gerçeğini bölerek yollar.
2. **Yeniden arama.** Yanıtsız kalan SYN'i yedek bir kaynak porttan yeniden yollar; kazanan yol için akışın bütün paketlerinde port çevirisi yapar. Uygulama hiçbir şey fark etmez (ISN ve seçenekler aynıdır).
3. **DNS.** Giden UDP/53 sorgularını yakalar, yanıtı DoH ile alır ve asıl DNS sunucusundan gelmiş gibi içeri enjekte eder. Bağdaştırıcı ayarına dokunmaz; IPv4, IPv6 ve bağlantı-yerel adreslerde çalışır.

macOS: `SONdpi.app` (evrensel ikili, `tools/macos-paket.sh`). Argümansız menü çubuğu uygulaması (`src/macos/app.rs`), `dev` sistem ayarına dokunmadan proxy'yi konsolda çalıştırır. Taşınabilir çekirdek: `proxy.rs` (HTTP CONNECT, mutlak HTTP, SOCKS5, PAC, ilk kaydı bölme), `dial.rs` (Happy Eyeballs + 250 ms'de yarışan yeniden arama), `resolve.rs` (DoH, önbellek, eşzamanlı sorgu birleştirme). Yalnızca macOS: `macos/doh.rs` (SecureTransport), `macos/sysproxy.rs` (networksetup; özgün ayar önce `~/Library/Application Support/SONdpi/proxy-saved.tsv`'ye yazılır, gerekirse yönetici diyaloğu), `macos/core.rs` (anahtar, iş parçacığı, 10 sn'de bir bekçi), `macos/objc.rs` (elle bildirilmiş Objective-C çalışma zamanı), `macos/autostart.rs` (LaunchAgent). Simgeler `tools/macos-ikon-uret.swift` ile SVG çizimlerinden üretilir ve commit'lenir.

| Modül | İş | Sahibi |
|---|---|---|
| `api.rs`, `packet.rs`, `lib.rs`, `main.rs`, `Cargo.toml`, bu dosya | Ortak adlar, paket türü, birleştirme | Lider |
| `tls.rs`, `desync.rs` | ClientHello ayrıştırma/üretme, stratejiler (saf mantık) | Desync işçisi |
| `divert.rs`, `redial.rs`, `engine.rs`, `dev.rs` | WinDivert FFI, yeniden arama, paket döngüleri, geliştirme kipi | Motor işçisi |
| `doh.rs`, `dns.rs` | DoH istemcisi, yerel DNS yanıtlayıcı | DNS işçisi |
| `ipc.rs`, `service.rs`, `tray.rs`, `install.rs` | Kontrol borusu, servis, tepsi anahtarı, kurulum | Kabuk işçisi |

Modüller arası sözleşme, iskelet dosyalardaki `pub` imzalardır. İmzayı genişletebilirsin; var olanı değiştirmen gerekiyorsa raporunda yaz, lider birleştirir.

## Kurallar

- **Bağımlılık.** Tek crate `windows-sys`, yalnızca Windows'ta (`[target.'cfg(windows)']`). Yeni crate ekleme. `Cargo.toml` içinde yalnızca `windows-sys` özellik listesine satır eklenebilir; başka hiçbir satıra dokunma (sürüm numarası lidere aittir). macOS sistem çağrıları (libc, Security, AppKit, Objective-C çalışma zamanı) kaynakta elle bildirilir.
- **Dosya sahipliği.** Bir dosyaya aynı anda tek kişi yazar. Sana verilmeyen dosyaya dokunma; ihtiyacın varsa raporunda yaz.
- **Derleme klasörü.** Her işçi kendi `CARGO_TARGET_DIR` klasörünü kullanır (görevinde yazar); varsayılan `target/` lidere aittir.
- **Yönetici hakkı.** İşçiler yönetici gerektiren hiçbir şey çalıştırmaz, servis kurmaz, sürücü yüklemez, sistem ayarı değiştirmez. Motorun gerçek hatta denenmesi lidere aittir ve her deneme kullanıcının onayıyla yapılır.
- **Git.** Yalnızca lider commit atar. İşçiler `git add`, `commit`, `stash`, `reset`, `checkout`, `restore` çalıştırmaz. `git push` ve repo görünürlüğü kullanıcının onayına bağlıdır.
- **unsafe.** Yalnızca FFI sınırında; her blokta neden güvenli olduğunu söyleyen tek satır. Paket mantığı güvenli Rust'tır ve birim testi vardır.
- **Hata.** Motor ağın önünde durur: hiçbir ayrıştırma hatası panik üretmez; anlaşılmayan paket değiştirilmeden geçirilir. Bir iş parçacığı ölürse motor kendini kapatıp sürücü tanıtıcılarını bırakır (yarım çalışan motor, kapalı motordan kötüdür).
- **Dış varlık.** İndirme (WinDivert'in resmî paketi dahil) kullanıcının onayına bağlıdır. `vendor/windivert/` içindekiler GoodbyeDPI 0.2.3rc3 paketinden gelen WinDivert 2.2 dosyalarıdır; lisansı yanındadır.

## Derleme ve test

- `cargo test` saf mantığı sınar; `cargo build --release` exe'yi üretir. Uyarısız derlenmeli. Mac'te Windows kodunu da denetle: `cargo check --target x86_64-pc-windows-msvc --all-targets`.
- Gerçek hat ölçümleri `tools/` altındaki Node betikleriyle yapılır (yalnızca geliştirme için): `probe.js` (TLS el sıkışması, gerçek IP'ye sabitlenmiş), `synprobe.js` (yalnızca TCP bağlantısı; kayıp SYN oranı), `tuple.js` (aynı kaynak portu yeniden deneme).
- Motoru denemek yönetici hakkı ister. Açık kalan, istek dinleyen yönetici yardımcısı kurma: bu yol güvenliği zayıflattığı için reddedildi (2026-11-13). Her deneme, ne yapacağı önceden kullanıcıya söylenen ve kullanıcının onayladığı tek seferlik bir çalıştırmadır: motoru belli bir süre açar, ölçer, kapatır ve çıkar.
- Bu makinede kurulu `GoodbyeDPI` servisi motorla aynı anda çalışmamalı; deneme sırasında durdurulur, deneme bitince yeniden başlatılır (kullanıcının interneti ona bağlı).
- Akıcılığı ve gerçek uygulamaları (Discord uygulaması, sesli kanal) lider ölçemez; kullanıcıya bırakılır ve raporda ayrı yazılır.
