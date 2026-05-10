# NetProbe: UDP Tabanlı Güvenilir Dosya Aktarımı, Trafik İzleme ve Ağ Performans Analizi

Bu proje, Bilgisayar Ağları dersi dönem projesi föyünde istenen **UDP üzerinde güvenilir dosya aktarımı**, **trafik/olay loglama** ve **ağ performans analizi** bileşenlerini içeren Python tabanlı bir uygulamadır.

GitHub bağlantısı:

```text
https://github.com/Rima2002/netprobe
```

## Projenin Amacı

NetProbe, UDP'nin doğasında bulunmayan güvenilirlik mekanizmalarını uygulama katmanında kendisi uygular. Projede hazır dosya aktarım kütüphanesi kullanılmaz. Dosya aktarımı doğrudan Python `socket` modülü ile UDP üzerinden yapılır.

Amaçlar:

- UDP istemci-sunucu mimarisini kurmak
- Dosyayı paketlere bölerek UDP ile aktarmak
- Sequence number, ACK, timeout ve retransmission mekanizmalarını uygulamak
- Duplicate paketleri tespit edip aynı veriyi ikinci kez yazmamak
- Aktarım sonunda SHA-256 ile dosya bütünlüğünü doğrulamak
- Trafik olaylarını CSV/JSON olarak kaydetmek
- Throughput, goodput, RTT, retransmission ve completion time metriklerini analiz etmek
- Deney sonuçlarını grafiklerle desteklemek

## Proje Yapısı

```text
netprobe/
  client.py          UDP istemci kodu
  server.py          UDP sunucu kodu
  protocol.py        Paket formatı, checksum ve SHA-256 yardımcıları
  logger.py          CSV/JSON olay loglama sistemi
  analyzer.py        Performans analizi ve grafik üretimi
  experiments.py     Otomatik deney senaryoları
  config.py          Varsayılan ayarlar
  requirements.txt   Gerekli Python kütüphaneleri
  test_files/        Test dosyaları
  received_files/    Sunucuda yeniden oluşturulan dosyalar
  logs/              İstemci ve sunucu logları
  results/           Analiz çıktıları ve grafikler
```

## Kullanılan Teknolojiler

Python modülleri:

- `socket`
- `time`
- `hashlib`
- `struct`
- `argparse`
- `csv`
- `json`
- `random`
- `os`
- `subprocess`

Analiz ve grafik için:

- `pandas`
- `matplotlib`

Kurulum:

```cmd
cd "C:\Users\Rima Farah Eleuch\OneDrive\Desktop\SPRING SEMESTER 2026\BilgisayarAglari_1\Proje\netprobe"
python -m pip install -r requirements.txt
```

Windows `cmd` terminalinde `python` komutu çalışmazsa:

```cmd
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -m pip install -r requirements.txt
```

## Paket Formatı

Her veri paketi aşağıdaki alanları içerir:

```text
packet type | sequence number | total packet count | payload length | checksum | payload
```

Paket başlığı `protocol.py` içinde `struct` ile oluşturulur:

```text
!BIIH32s
```

Bu alanlar:

- `packet type`: START, DATA, ACK, FIN, FIN_ACK gibi paket türleri
- `sequence number`: paket sıra numarası
- `total packet count`: toplam veri paketi sayısı
- `payload length`: veri uzunluğu
- `checksum`: paketin payload alanı için SHA-256 checksum
- `payload`: dosya parçası veya kontrol bilgisi

## Güvenilir Aktarım Mekanizması

Projede temel güvenilirlik yöntemi olarak **Stop-and-Wait ARQ** kullanılır.

Çalışma mantığı:

1. İstemci dosyayı parçalara böler.
2. Her parçaya sequence number verilir.
3. İstemci bir DATA paketi gönderir.
4. Aynı paket için ACK gelene kadar yeni veri paketi göndermez.
5. ACK belirlenen timeout süresi içinde gelmezse aynı paket yeniden gönderilir.
6. Varsayılan maksimum yeniden gönderim sayısı `5` olarak ayarlanmıştır.
7. Paket maksimum deneme sayısından sonra iletilemezse aktarım başarısız kabul edilir ve loglara yazılır.
8. Sunucu duplicate sequence number görürse aynı payload'u tekrar kaydetmez; sadece doğru ACK'i yeniden gönderir.
9. Aktarım sonunda sunucu dosyayı doğru sırada birleştirir.
10. Orijinal dosya SHA-256 hash değeri ile yeniden oluşturulan dosyanın SHA-256 hash değeri karşılaştırılır.

## Sunucuyu Çalıştırma

Birinci terminal:

```cmd
cd "C:\Users\Rima Farah Eleuch\OneDrive\Desktop\SPRING SEMESTER 2026\BilgisayarAglari_1\Proje\netprobe"
python server.py --host 127.0.0.1 --port 5005 --once
```

Alternatif tam Python yolu:

```cmd
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" server.py --host 127.0.0.1 --port 5005 --once
```

Duplicate paket davranışını loglarda daha görünür yapmak için ACK kaybı simülasyonu:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once --ack-loss-rate 0.2
```

## İstemciyi Çalıştırma

İkinci terminal:

```cmd
cd "C:\Users\Rima Farah Eleuch\OneDrive\Desktop\SPRING SEMESTER 2026\BilgisayarAglari_1\Proje\netprobe"
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files\medium.bin
```

Parametreli örnek:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files\medium.bin --packet-size 1024 --timeout 1.0 --loss-rate 0.1 --max-retries 5
```

Parametreler:

- `--server-ip`: sunucu IP adresi
- `--server-port`: sunucu portu
- `--file`: gönderilecek dosya yolu
- `--packet-size`: veri paketi payload boyutu
- `--timeout`: ACK bekleme süresi
- `--loss-rate`: yapay paket kaybı oranı
- `--max-retries`: maksimum yeniden gönderim sayısı

## SHA-256 Bütünlük Kontrolü

Aktarımdan sonra orijinal ve alınan dosyanın hash değerlerini kontrol etmek için:

```cmd
certutil -hashfile test_files\medium.bin SHA256
certutil -hashfile received_files\medium.bin SHA256
```

İki hash değeri aynı olmalıdır.

Program içinde de bütünlük kontrolü yapılır ve loglara şu alan yazılır:

```text
integrity_ok=True
```

Analyzer çıktısında başarılı aktarım için:

```json
"integrity_ok": true
```

## Loglama

İstemci ve sunucu logları `logs/` klasörüne CSV ve JSON olarak kaydedilir.

Loglanan başlıca bilgiler:

- paket sıra numarası
- paket gönderim zamanı
- ACK alınma zamanı
- RTT
- timeout olayları
- retransmission sayısı
- duplicate paket sayısı
- başarılı paket sayısı
- başarısız paket sayısı
- toplam aktarım süresi
- orijinal dosya boyutu
- aktarılan byte sayısı
- SHA-256 bütünlük sonucu

Log dosyalarını görmek için:

```cmd
dir logs
```

## Analiz Çalıştırma

Önce en yeni client log dosyasını bulun:

```cmd
dir logs\client_transfer_*.csv
```

Sonra analyzer çalıştırın:

```cmd
python analyzer.py --log logs\client_transfer_YYYYMMDD_HHMMSS_mmm.csv
```

Gerçek dosya adı örneği:

```cmd
python analyzer.py --log logs\client_transfer_20260510_175033_036.csv
```

Analiz çıktıları:

```text
results/analysis_summary.csv
results/analysis_summary.json
```

Hesaplanan metrikler:

- throughput
- goodput
- packet loss rate
- retransmission count
- retransmission rate
- average RTT
- completion time
- duplicate count
- integrity status

## Deneyleri Çalıştırma

Deney betiği test dosyalarını otomatik üretir:

```text
test_files/small.bin   >= 10 KB
test_files/medium.bin  >= 1 MB
test_files/large.bin   >= 10 MB
```

Deneyleri çalıştırmak için:

```cmd
python experiments.py
```

Deney sonuçları:

```text
results/experiment_results.csv
```

CSV içinde rapor yazmayı kolaylaştıran alanlar:

```text
scenario, packet_size, timeout, loss_rate, file_size, throughput, goodput,
completion_time, retransmission_count, retransmission_rate, packet_loss_rate,
average_rtt, duplicate_count, integrity_ok
```

## Deney Senaryoları

Föyde önerilen deneylerden proje içinde kullanılan başlıca senaryolar:

1. **Paket boyutunun etkisi**
   - Farklı packet size değerleri ile throughput, goodput ve completion time karşılaştırılır.

2. **Timeout değerinin etkisi**
   - Farklı timeout değerlerinin retransmission count ve completion time üzerindeki etkisi incelenir.

3. **Yapay kayıp oranının etkisi**
   - Farklı loss rate değerleri ile retransmission rate, throughput ve goodput karşılaştırılır.

4. **Farklı dosya boyutları**
   - `small.bin`, `medium.bin` ve `large.bin` dosyaları deney veya demo için kullanılabilir.

## Grafikler

Deneylerden sonra `results/` klasöründe aşağıdaki grafikler oluşur:

```text
packet_size_throughput_goodput.png
packet_size_completion_time.png
timeout_retransmission_count.png
timeout_completion_time.png
loss_rate_throughput_goodput.png
loss_rate_retransmission_rate.png
```

Grafikleri açmak için:

```cmd
start results\packet_size_throughput_goodput.png
start results\timeout_retransmission_count.png
start results\loss_rate_retransmission_rate.png
```

## Teknik Rapor İçin Önerilen Bölümler

PDF föyüne göre teknik raporda şu bölümlerin bulunması beklenir:

- Giriş
- Problem tanımı
- Sistem mimarisi
- Protokol tasarımı
- Gerçekleme detayları
- Deney ortamı
- Performans metrikleri
- Sonuçlar ve tartışma
- Karşılaşılan sorunlar ve çözüm yaklaşımları
- Sonuç ve gelecekte yapılabilecek geliştirmeler

Raporda sadece grafik koymak yeterli değildir. Her deney sonucu protokol davranışıyla ilişkilendirilerek teknik olarak yorumlanmalıdır.

Örnek yorum başlıkları:

- Paket boyutu artınca throughput nasıl değişti?
- Timeout değeri retransmission sayısını nasıl etkiledi?
- Kayıp oranı goodput ve completion time üzerinde nasıl bir etki oluşturdu?
- Duplicate paketler nasıl ele alındı?
- SHA-256 bütünlük kontrolü neyi doğruladı?

## Teslim İçeriği

Föye göre teslim:

```text
.zip dosyası + GitHub bağlantısı + teknik rapor (PDF)
```

`.zip` içinde en az şunlar bulunmalıdır:

- kaynak kodlar
- teknik rapor PDF dosyası
- README dosyası
- varsa loglar, grafikler veya deney sonuçları

GitHub bağlantısı README içinde açıkça verilmiştir:

```text
https://github.com/Rima2002/netprobe
```

## Uygunluk Notları

- Hazır dosya aktarım kütüphanesi kullanılmamıştır.
- İstemci-sunucu haberleşmesi doğrudan UDP socket programming ile yapılır.
- Güvenilirlik mekanizması uygulama katmanında manuel olarak geliştirilmiştir.
- Sequence number, ACK, timeout, retransmission ve duplicate paket kontrolü uygulanmıştır.
- Aktarım sonunda SHA-256 ile dosya bütünlüğü doğrulanır.
- Dış kütüphaneler yalnızca analiz ve grafik amaçlı `pandas` ve `matplotlib` olarak kullanılmıştır.

