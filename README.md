# NetProbe: UDP Reliable File Transfer

NetProbe, UDP uzerinde calisan guvenilir dosya aktarimi, trafik loglama ve ag performans analizi projesidir. UDP kendi basina teslim garantisi vermedigi icin proje; sequence number, ACK, timeout, retransmission, duplicate packet kontrolu ve SHA-256 butunluk dogrulamasini uygulama katmaninda elle uygular.

Ana aktarim yontemi: **UDP + Stop-and-Wait ARQ**.

## Projenin Amaci

- UDP istemci-sunucu mimarisi kurmak
- Dosyayi paketlere bolerek UDP datagramlari ile aktarmak
- Her DATA paketi icin ACK beklemek
- ACK gelmezse timeout sonrasinda ayni paketi yeniden gondermek
- Duplicate paketleri ikinci kez dosyaya yazmamak
- Aktarim sonunda SHA-256 ile dosya butunlugunu dogrulamak
- CSV/JSON loglarindan throughput, goodput, RTT, completion time ve retransmission metrikleri uretmek
- Deney sonuclarini grafik ve teknik yorumlarla rapora hazir hale getirmek

## Klasor Yapisi

```text
netprobe/
  client.py                 UDP Stop-and-Wait istemcisi
  server.py                 UDP sunucusu ve dosya yeniden olusturma
  protocol.py               Paket formati, checksum ve SHA-256 yardimcilari
  logger.py                 CSV/JSON olay loglama
  analyzer.py               Metrik, grafik ve teknik yorum uretimi
  experiments.py            Otomatik deney senaryolari
  tcp_client.py             Bonus TCP karsilastirma istemcisi
  tcp_server.py             Bonus TCP karsilastirma sunucusu
  tests/                    Unit testler
  test_files/               Ornek test dosyalari
  received_files/           Sunucuda olusturulan dosyalar
  logs/                     Ornek ve yeni transfer loglari
  results/                  Deney CSV/JSON, grafikler ve teknik yorum
```

Teslim icin beklenen temiz ciktilar:

```text
test_files/
  small.txt
  medium.bin
  large.bin

logs/
  sample_client_log.csv
  sample_server_log.csv

results/
  experiment_results.csv
  experiment_results.json
  technical_interpretation.txt
  file_size_throughput_goodput.png
  file_size_completion_time.png
  packet_size_throughput_goodput.png
  packet_size_completion_time.png
  timeout_retransmission_count.png
  timeout_completion_time.png
  loss_rate_throughput_goodput.png
  loss_rate_retransmission_rate.png
```

Eski timestamp'li loglar ve tekrar eden deney grafikleri `archive/` altina tasinabilir. `logs/` klasoru demo ve rapor icin okunabilir ornek loglari tutar.

## Protokol Ozeti

Her UDP paketi su alanlardan olusur:

```text
packet type | sequence number | total packet count | payload length | checksum | payload
```

Paket basligi `protocol.py` icinde `struct` ile tanimlanir:

```text
!BIIH32s
```

Paket turleri:

- `START`: Dosya adi, toplam paket sayisi, dosya boyutu ve SHA-256 metadata bilgisini tasir.
- `DATA`: Dosya parcasini tasir.
- `ACK`: START veya DATA paketinin alindigini bildirir.
- `FIN`: Aktarimin bittigini ve istemcinin beklenen SHA-256 hash degerini bildirir.
- `FIN_ACK`: Sunucunun yeniden olusturdugu dosya icin butunluk sonucunu dondurur.

## Stop-and-Wait ARQ

NetProbe varsayilan ve ana mekanizma olarak Stop-and-Wait ARQ kullanir:

1. Istemci bir paket gonderir.
2. Ayni sequence number icin ACK bekler.
3. ACK gelirse bir sonraki pakete gecer.
4. Timeout olursa ayni paketi yeniden gonderir.
5. Maksimum yeniden gonderim sayisi varsayilan olarak `5` tir.
6. Sunucu duplicate DATA paketi alirsa veriyi tekrar yazmaz, sadece ACK'i yeniden gonderir.

Bu projede sliding window ana mekanizma degildir; karisiklik olmamasi icin UDP istemcisinde yalnizca Stop-and-Wait akisi tutulmustur.

## Kurulum

```cmd
python -m pip install -r requirements.txt
```

Gerekli dis kutuphaneler sadece analiz ve grafik icindir:

```text
pandas
matplotlib
```

Dosya aktarimi icin hazir dosya transfer kutuphanesi kullanilmaz; aktarim raw UDP socket programming ile yapilir.

## Server Calistirma

Birinci terminal:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once
```

ACK kaybi simule etmek icin:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once --ack-loss-rate 0.2
```

## Client Calistirma

Ikinci terminal:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/medium.bin
```

Parametreli ornek:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/medium.bin --packet-size 1024 --timeout 1.0 --loss-rate 0.1 --max-retries 5
```

Onemli parametreler:

- `--packet-size`: DATA payload boyutu
- `--timeout`: ACK bekleme suresi
- `--loss-rate`: istemci tarafinda yapay paket kaybi
- `--max-retries`: bir paket icin maksimum yeniden gonderim sayisi

## Analyzer Calistirma

En yeni client logunu analiz etmek icin:

```cmd
python analyzer.py --log logs/sample_client_log.csv
```

Analyzer su dosyalari uretir:

```text
results/analysis_summary.csv
results/analysis_summary.json
```

Hesaplanan metrikler:

- `throughput`: retransmission ve kayip denemeleri dahil gonderilmeye calisilan DATA byte / sure
- `goodput`: basariyla yeniden olusturulan orijinal dosya byte / sure
- `packet_loss_rate`
- `retransmission_count`
- `retransmission_rate`
- `average_rtt`
- `completion_time`
- `duplicate_count`
- `integrity_ok`

## Olay Loglari

Aktarim sirasinda istemci ve sunucu olaylari `logger.py` ile CSV/JSON olarak kaydedilir. Ornek loglar:

```text
logs/sample_client_log.csv
logs/sample_server_log.csv
```

Loglarda takip edilen temel olaylar:

- `transfer_started`: aktarim parametreleri ve dosya bilgileri
- `packet_sent`: gonderilen START/DATA/FIN paketleri
- `ack_received`: istemcinin aldigi ACK/FIN_ACK cevaplari
- `timeout`: ACK bekleme suresinin dolmasi
- `simulated_packet_loss`: deney icin yapay olarak gonderilmeyen DATA paketi
- `packet_failed`: maksimum yeniden gonderim denemesinden sonra basarisiz paket
- `packet_received`: sunucunun aldigi paketler
- `duplicate_packet_ignored`: tekrar gelen DATA paketinin ikinci kez yazilmamasi
- `file_reconstructed`: sunucuda dosyanin yeniden olusturulmasi
- `transfer_completed`: aktarimin tamamlanmasi ve SHA-256 sonucunun kaydedilmesi

Bu olaylar; timeout sayisi, retransmission count/rate, RTT, packet loss rate, throughput,
goodput ve completion time metriklerinin hesaplanmasi icin kullanilir.

## Deneyleri Calistirma

```cmd
python experiments.py
```

Deneyler su senaryolari uretir:

- farkli dosya boyutlari
- farkli paket boyutlari
- farkli timeout degerleri
- farkli yapay kayip oranlari
- bonus olarak UDP/TCP karsilastirma satirlari

Deney ciktilari:

```text
results/experiment_results.csv
results/experiment_results.json
results/technical_interpretation.txt
results/file_size_throughput_goodput.png
results/file_size_completion_time.png
results/packet_size_throughput_goodput.png
results/packet_size_completion_time.png
results/timeout_retransmission_count.png
results/timeout_completion_time.png
results/loss_rate_throughput_goodput.png
results/loss_rate_retransmission_rate.png
```

Grafikler farkli birimlerdeki metrikleri ayni y ekseninde karistirmayacak sekilde ayrilmistir:

- `file_size_throughput_goodput.png`: kucuk, orta ve buyuk dosya aktariminda throughput/goodput degisimini gosterir.
- `file_size_completion_time.png`: dosya boyutunun toplam aktarim suresine etkisini gosterir.
- `packet_size_throughput_goodput.png`: paket boyutu arttikca throughput ve goodput degisimini gosterir. Kayip olmadiginda iki metrik birbirine cok yakin olabilir.
- `packet_size_completion_time.png`: paket boyutunun toplam aktarim suresine etkisini gosterir.
- `timeout_retransmission_count.png`: timeout degerinin yeniden gonderilen paket sayisina etkisini gosterir.
- `timeout_completion_time.png`: timeout degerinin aktarim tamamlanma suresine etkisini gosterir.
- `loss_rate_throughput_goodput.png`: yapay kayip oraninin throughput ve goodput uzerindeki etkisini gosterir.
- `loss_rate_retransmission_rate.png`: yapay kayip oraninin retransmission rate uzerindeki etkisini ayri bir oranda gosterir.

`technical_interpretation.txt`, rapora dogrudan eklenebilecek kisa teknik Turkce yorumlar icerir.
Bu yorumlar deney parametrelerinin retransmission, bekleme suresi, goodput ve completion time
uzerindeki etkisini protokol davranisiyla iliskilendirir.

## Unit Testler

```cmd
python -m unittest discover tests
```

Testler sunlari kontrol eder:

- checksum hesaplama
- DATA packet olusturma/parse etme
- ACK packet olusturma/parse etme
- ayni dosya icin SHA-256 sonucunun sabit olmasi
- duplicate packet'in ikinci kez saklanmamasi
- analyzer metriklerinin beklenen degerleri hesaplamasi

## SHA-256 Kontrolu

Windows ortaminda manuel kontrol:

```cmd
certutil -hashfile test_files\medium.bin SHA256
certutil -hashfile received_files\medium.bin SHA256
```

Iki hash ayniysa aktarim basarilidir. Program bu kontrolu otomatik yapar ve loglarda `integrity_ok=true` olarak yazar.

## GitHub

```text
https://github.com/Rima2002/netprobe
```

## Teslim Notu

Final teslim icin `.zip` icinde kaynak kodlar, README, teknik rapor PDF'i, GitHub baglantisi,
ornek loglar, deney sonuclari, grafikler ve test dosyalari bulunmalidir. Teknik raporda yalnizca
grafik verilmemeli; paket boyutu, timeout ve kayip oraninin protokol davranisina etkisi
retransmission, bekleme suresi, goodput ve completion time acisindan yorumlanmalidir.
