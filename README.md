# NetProbe: UDP Tabanlı Güvenilir Dosya Aktarımı

NetProbe, UDP üzerinde çalışan güvenilir dosya aktarımı, trafik loglama ve ağ performans analizi projesidir. UDP kendi başına teslim garantisi vermediği için proje; sequence number, ACK, timeout, retransmission, duplicate packet kontrolü ve SHA-256 bütünlük doğrulamasını uygulama katmanında elle uygular.

Ana aktarım yöntemi: **UDP + Stop-and-Wait ARQ**.

## Projenin Amacı

- UDP istemci-sunucu mimarisi kurmak
- Dosyayı paketlere bölerek UDP datagramları ile aktarmak
- Her DATA paketi için ACK beklemek
- ACK gelmezse timeout sonrasında aynı paketi yeniden göndermek
- Duplicate paketleri ikinci kez dosyaya yazmamak
- Aktarım sonunda SHA-256 ile dosya bütünlüğünü doğrulamak
- CSV/JSON loglarından throughput, goodput, RTT, completion time ve retransmission metrikleri üretmek
- Deney sonuçlarını grafik ve teknik yorumlarla rapora hazır hale getirmek

## Klasör Yapısı

```text
netprobe/
  client.py                 UDP Stop-and-Wait istemcisi
  server.py                 UDP sunucusu ve dosya yeniden oluşturma
  protocol.py               Paket formatı, checksum ve SHA-256 yardımcıları
  logger.py                 CSV/JSON olay loglama
  analyzer.py               Metrik, grafik ve teknik yorum üretimi
  experiments.py            Otomatik deney senaryoları
  tcp_client.py             Bonus TCP karşılaştırma istemcisi
  tcp_server.py             Bonus TCP karşılaştırma sunucusu
  tests/                    Unit testler
  test_files/               Örnek test dosyaları
  received_files/           Sunucuda oluşturulan dosyalar
  logs/                     Örnek ve yeni transfer logları
  results/                  Deney CSV/JSON, grafikler ve teknik yorum
```

Teslim için beklenen temiz çıktılar:

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

Eski timestamp'li loglar ve tekrar eden deney grafikleri `archive/` altına taşınabilir. `logs/` klasörü demo ve rapor için okunabilir örnek logları tutar.

## Protokol Özeti

Her UDP paketi şu alanlardan oluşur:

```text
packet type | sequence number | total packet count | payload length | checksum | payload
```

Paket başlığı `protocol.py` içinde `struct` ile tanımlanır:

```text
!BIIH32s
```

Paket türleri:

- `START`: Dosya adı, toplam paket sayısı, dosya boyutu ve SHA-256 metadata bilgisini taşır.
- `DATA`: Dosya parçasını taşır.
- `ACK`: START veya DATA paketinin alındığını bildirir.
- `FIN`: Aktarımın bittiğini ve istemcinin beklenen SHA-256 hash değerini bildirir.
- `FIN_ACK`: Sunucunun yeniden oluşturduğu dosya için bütünlük sonucunu döndürür.

## Stop-and-Wait ARQ

NetProbe varsayılan ve ana mekanizma olarak Stop-and-Wait ARQ kullanır:

1. İstemci bir paket gönderir.
2. Aynı sequence number için ACK bekler.
3. ACK gelirse bir sonraki pakete geçer.
4. Timeout olursa aynı paketi yeniden gönderir.
5. Maksimum yeniden gönderim sayısı varsayılan olarak `5`tir.
6. Sunucu duplicate DATA paketi alırsa veriyi tekrar yazmaz, sadece ACK'i yeniden gönderir.

Bu projede sliding window ana mekanizma değildir; karışıklık olmaması için UDP istemcisinde yalnızca Stop-and-Wait akışı tutulmuştur.

## Kurulum

```cmd
python -m pip install -r requirements.txt
```

Gerekli dış kütüphaneler sadece analiz ve grafik içindir:

```text
pandas
matplotlib
```

Dosya aktarımı için hazır dosya transfer kütüphanesi kullanılmaz; aktarım raw UDP socket programming ile yapılır.

## Server Çalıştırma

Birinci terminal:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once
```

ACK kaybı simüle etmek için:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once --ack-loss-rate 0.2
```

## Client Çalıştırma

İkinci terminal:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/medium.bin
```

Parametreli örnek:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/medium.bin --packet-size 1024 --timeout 1.0 --loss-rate 0.1 --max-retries 5
```

Önemli parametreler:

- `--packet-size`: DATA payload boyutu
- `--timeout`: ACK bekleme süresi
- `--loss-rate`: istemci tarafında yapay paket kaybı
- `--max-retries`: bir paket için maksimum yeniden gönderim sayısı

## Analyzer Çalıştırma

En yeni client logunu analiz etmek için:

```cmd
python analyzer.py --log logs/sample_client_log.csv
```

Analyzer şu dosyaları üretir:

```text
results/analysis_summary.csv
results/analysis_summary.json
```

Hesaplanan metrikler:

- `throughput`: retransmission ve kayıp denemeleri dahil gönderilmeye çalışılan DATA byte / süre
- `goodput`: başarıyla yeniden oluşturulan orijinal dosya byte / süre
- `packet_loss_rate`
- `retransmission_count`
- `retransmission_rate`
- `average_rtt`
- `completion_time`
- `duplicate_count`
- `integrity_ok`

## Olay Logları

Aktarım sırasında istemci ve sunucu olayları `logger.py` ile CSV/JSON olarak kaydedilir. Örnek loglar:

```text
logs/sample_client_log.csv
logs/sample_server_log.csv
```

Loglarda takip edilen temel olaylar:

- `transfer_started`: aktarım parametreleri ve dosya bilgileri
- `packet_sent`: gönderilen START/DATA/FIN paketleri
- `ack_received`: istemcinin aldığı ACK/FIN_ACK cevapları
- `timeout`: ACK bekleme süresinin dolması
- `simulated_packet_loss`: deney için yapay olarak gönderilmeyen DATA paketi
- `packet_failed`: maksimum yeniden gönderim denemesinden sonra başarısız paket
- `packet_received`: sunucunun aldığı paketler
- `duplicate_packet_ignored`: tekrar gelen DATA paketinin ikinci kez yazılmaması
- `file_reconstructed`: sunucuda dosyanın yeniden oluşturulması
- `transfer_completed`: aktarımın tamamlanması ve SHA-256 sonucunun kaydedilmesi

Bu olaylar; timeout sayısı, retransmission count/rate, RTT, packet loss rate, throughput, goodput ve completion time metriklerinin hesaplanması için kullanılır.

## Deneyleri Çalıştırma

```cmd
python experiments.py
```

Deneyler şu senaryoları üretir:

- farklı dosya boyutları
- farklı paket boyutları
- farklı timeout değerleri
- farklı yapay kayıp oranları
- bonus olarak UDP/TCP karşılaştırma satırları

Deney çıktıları:

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

Grafikler farklı birimlerdeki metrikleri aynı y ekseninde karıştırmayacak şekilde ayrılmıştır:

- `file_size_throughput_goodput.png`: küçük, orta ve büyük dosya aktarımında throughput/goodput değişimini gösterir.
- `file_size_completion_time.png`: dosya boyutunun toplam aktarım süresine etkisini gösterir.
- `packet_size_throughput_goodput.png`: paket boyutu arttıkça throughput ve goodput değişimini gösterir. Kayıp olmadığında iki metrik birbirine çok yakın olabilir.
- `packet_size_completion_time.png`: paket boyutunun toplam aktarım süresine etkisini gösterir.
- `timeout_retransmission_count.png`: timeout değerinin yeniden gönderilen paket sayısına etkisini gösterir.
- `timeout_completion_time.png`: timeout değerinin aktarım tamamlanma süresine etkisini gösterir.
- `loss_rate_throughput_goodput.png`: yapay kayıp oranının throughput ve goodput üzerindeki etkisini gösterir.
- `loss_rate_retransmission_rate.png`: yapay kayıp oranının retransmission rate üzerindeki etkisini ayrı bir oranda gösterir.

`technical_interpretation.txt`, rapora doğrudan eklenebilecek kısa teknik Türkçe yorumlar içerir. Bu yorumlar deney parametrelerinin retransmission, bekleme süresi, goodput ve completion time üzerindeki etkisini protokol davranışıyla ilişkilendirir.

## Unit Testler

```cmd
python -m unittest discover tests
```

Testler şunları kontrol eder:

- checksum hesaplama
- DATA packet oluşturma/parse etme
- ACK packet oluşturma/parse etme
- aynı dosya için SHA-256 sonucunun sabit olması
- duplicate packet'in ikinci kez saklanmaması
- analyzer metriklerinin beklenen değerleri hesaplaması

## SHA-256 Kontrolü

Windows ortamında manuel kontrol:

```cmd
certutil -hashfile test_files\medium.bin SHA256
certutil -hashfile received_files\medium.bin SHA256
```

İki hash aynıysa aktarım başarılıdır. Program bu kontrolü otomatik yapar ve loglarda `integrity_ok=true` olarak yazar.

## GitHub

```text
https://github.com/Rima2002/netprobe
```

