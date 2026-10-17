# Açık kaynak yayın ve Windows imzası

## 0.8 çalışma dalının yayın engeli

Aynı masaüstünde sanal servis kimliğiyle otomatik açılış kodu geliştirildi.
Yerel başlatıcı Windows Defender tarafından `Trojan:Win32/Bearfoos.B!ml` olarak
engellendi; yanlış alarm olduğu henüz doğrulanmadı. 0.8 paketi yayımlanmadı.
`tools/check-defender.ps1` uygulama/kurucu çalıştırılmadan ve paketleme sırasında
tarama yapar; tehdit veya tarama yokluğunda dağıtımı durdurur. Defender istisnası,
kapatma veya karantinadan geri alma kullanılmaz. Ayrıntılar: `DESKTOP-SERVICE.md`.

## Yayımlanan 0.7 sürümü

**Durum: 0.7.0 deneysel önizleme.** Kaynak kod MIT; çekirdek sürücüsü imzasız ve
çalışma testinden geçmedi. Masaüstü uygulaması yalnızca ayrı Windows hesabı,
gerçek oturum sahibi ve erişim izinleri doğrulanınca Discord’u açar. Setup.exe
hesap kurulumunu başlatır; genel RAT engelleme veya çekirdek koruması ilan edilmez.

## 1. GitHub deposu

Depo: <https://github.com/yuefdev/discord-guard>. MIT lisansı, güvenlik politikası,
katkı yönergesi ve CI mevcut. Anahtar, PFX, token, WDK, derleme ve kişisel veri
depoya girmez. `tools/package_release.py` yalnızca kaynak izin listesini arşivler.

Depoda özel güvenlik bildirimi, ana dal koruması ve `release` environment için
inceleyen kişi koşulu etkinleştirilmelidir. İmzalama anahtarları PR işlerine verilmez.
Önizleme CI imza anahtarı kullanmaz.

## 2. Otomatik derleme

`ci.yml`, Windows runner üzerinde sabit Python bağımlılıklarını yükler; testleri,
Qt arayüz açılışını, native derlemeyi ve politika testlerini çalıştırır. Sürücü
paketinin Microsoft WDK SHA-512 değeri sabittir. Çıktı kaynak, bağımlılık lisansları,
SHA256 ve açık deneysel durum manifesti içerir. GitHub işinin çevrim içi geçtiği,
yereldeki başarının yerine varsayılmaz.

`release-draft.yml` elle seçilen mevcut tag’den yeniden derler. Sonuçları yalnızca
taslak ön sürüme ekler. `v0.6.0` etiketi yayın komutuna kabuk metni olarak sokulmaz.
İş akışı üretim sertifikası veya Microsoft onayı oluşturmaz.

## 3. Windows uygulama imzası

Uygulama `.exe` ve broker `.exe` için güvenilir bir Authenticode kod imzalama
sertifikası veya uygun yönetilen imzalama hizmeti gerekir. Gerçek kişi/kurum
doğrulaması ve ücretler sağlayıcıya bağlıdır. Donanım tokeni/anahtar kasası tercih
edilir. Anahtar kaynak veya CI artifact içine aktarılmaz.

```powershell
.\tools\sign-app.ps1 -Artifact 'C:\Release\DiscordGuard.exe' `
  -CertificateThumbprint 'GERCEK_40_KARAKTERLIK_PARMAK_IZI' `
  -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
```

Komut gerçek parmak izi ister; örnekteki yer tutucu kabul edilmez. SHA-256 ve
RFC3161 zaman damgası kullanılır. İmza SmartScreen itibarını hemen sağlamaz.

## 4. Windows çekirdek sürücüsü kabulü

Publisher sertifikasıyla `.sys` imzalamak, güncel perakende Windows’un kernel
politikasını tek başına karşılamaz. Microsoft Hardware Developer/Partner Center
kaydı ve uygun Microsoft sürücü imzalama yolu gerekir. Dashboard hesabında
geçerli EV sertifikası ilişkilendirme koşulu bulunur. Başvuru sertifikası hesaba
kayıtlı olmalıdır. Bu hesap/sertifika işlemleri kullanıcı/kurum adına otomatik
tamamlanamaz.

Geniş perakende dağıtım için WHCP/HLK yolunu hedefle. Attestation, HLK sertifikası
değildir; Microsoft’un güncel belgeleri bu yolu test senaryolarıyla sınırlar ve
Windows Update perakende yayını sağlamaz. Test imzası üretim onayı sayılmaz.

## 5. Paket ve altitude

Minifilter için Microsoft’tan uygun sınıf/altitude tahsisi gerekir. Laboratuvar
altitude değeri üretimde kullanılmaz. Aday INF şablonu hazır; sınıf ve load-order
grubu Microsoft tahsisiyle birlikte doğrulanmalıdır.

```powershell
python -B tools\prepare_submission.py --native 'C:\GuardCoreBuild' `
  --output 'C:\SubmissionCandidate' --provider 'Verified Publisher' `
  --altitude 'MICROSOFT_TARAFINDAN_TAHSIS_EDILEN_DEGER'
```

Bu komut da yer tutucuyu reddeder. `.sys`, hata ayıklama `.pdb` ve INF hazırlanır.
InfVerif/Inf2Cat, katalog, HLK sonuçları ve imzalı CAB ayrıca gerekir. Aday INF
henüz bu araçlardan geçmedi; teslimata hazır paket olarak gösterilmez.

## 6. Microsoft’a teslim

Doğrulanan INF/SYS/PDB/CAT aynı sürüme ait olmalı. Dashboard’un istediği klasörlü
CAB veya HLK teslim paketi hazırlanır, kayıtlı sertifikayla imzalanır ve Hardware
Dashboard üzerinden gönderilir. Hesap yetkili olduğunda resmî API otomasyonu
eklenebilir; bu depoda yetkisiz otomatik başvuru yoktur.

Microsoft’tan dönen dosya yeniden doğrulanır:

```powershell
.\tools\verify-driver.ps1 -Driver 'C:\MicrosoftReturned\GuardCore.sys' `
  -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
```

`/kp` politikası ve Microsoft imzası gerekir. Bir sertifikanın yerel olarak
güvenilir olması, Microsoft üretim imzasının yerine geçmez.

## 7. Yayın öncesi çalışma kanıtı

Temiz snapshot’lı VM’de normal Discord girişi/ses, yönetici ve standart kullanıcı
dosya erişimi, süreç izinleri, bağlantı kaybı, bozuk mesajlar, uyku/yeniden başlama,
HVCI ve Driver Verifier denenir. Sonuç, kullanılan dosyaların SHA256 değerleri ve
VM sürümüyle kaydedilir. Native yönergedeki matris tamamlanmalıdır.

**Güncelleme desteği halen eksik:** broker tek bir Discord sürümünü sabitler.
Üretimden önce güncelleme, crash-recovery, paket yükseltme ve kaldırma akışları
uygulanmalı/test edilmelidir. Sadece imza alarak bu eksik aşılmış olmaz.

## 8. Dağıtım ve lisanslar

Yayın için `onedir` Qt düzeni kullanılır; kullanıcı uyumlu LGPL kitaplıklarını
değiştirebilir. ZIP içinde LGPL/GPL metinleri, Python lisansı, üçüncü taraf
bildirimleri ve tam uygulama kaynak arşivi bulunur. İlgili Qt sürümünün karşılık
gelen kaynak arşivleri de lisans yükümlülüğüne uygun sunulmalıdır. WDK ve
Discord’un kapalı kaynak istemcisi bizim paketimize konulmaz.

Önizleme ve tek dosyalık kurulum EXE'sini paketlemek için:

```powershell
.\build.ps1 -OutputRoot 'C:\AppBuild' -Layout onedir
python -B native\build.py --output 'C:\GuardCoreBuild'
python -B tools\package_release.py --app 'C:\AppBuild\dist\DiscordGuard' `
  --native 'C:\GuardCoreBuild' --output 'C:\FreshPreview'
```

Paketleyici `DiscordGuard-0.7.0-Setup.exe` üretir ve `--smoke-test` ile hesap
oluşturmadan açıp kapatır. Kurucu, dosya hash'lerini doğrular; yükseltilmiş kurulum
penceresi kapanana kadar çıkarılan dosyaları tutar. UAC, yeni hesap parolası ve
Windows/Discord girişi kullanıcı etkileşimi gerektirir. Mevcut kurulumların üzerine
yazılmaz; yükseltme için önce belgelenmiş kaldırma akışı değerlendirilmelidir.

## Tamamlanması dışarıya bağlı olanlar

- Gerçek yayıncı kimliği, sertifika/anahtar erişimi ve Hardware hesabı.
- Microsoft altitude tahsisi, InfVerif/Inf2Cat/HLK ve üretim imzası.
- Temiz Windows VM çalışma matrisi ve ürün güncelleme/kurtarma desteği.

Bu adımlar tamamlanmadan “tek tıkla mevcut Discord’u yönetici RAT’a dayanıklı
yaptık” sonucu veya kararlı koruma sürümü ilan edilmez.

## Resmî kaynaklar

- <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request>
