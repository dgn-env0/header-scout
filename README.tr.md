# HeaderScout

HTTP yanıt header'larını hızlıca kontrol edip "hardening" eksiklerini ve bug bounty açısından triage sinyallerini gösteren hafif bir CLI aracıdır.

Yaygın güvenlik header'larını kontrol eder, her bulgu için `LOW / MEDIUM / HIGH` ciddiyet verir ve (hunter modunda) "raporlanabilirlik" notu ekler.

Bu araç exploit yapmaz. Amaç: eksik/zayıf savunma header'larını görüp, nerede neyi test etmeyi önceliklendireceğini hızla belirlemek.

## Özellikler

- Tek hedef veya dosyadan çoklu hedef tarama
- Yaygın güvenlik header kontrolleri (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP)
- **İki çıktı modu:**
  - **hunter (varsayılan):** FAIL/WARN odaklı + raporlanabilirlik notu
  - **hardening:** PASS/INFO dahil her şeyi gösterir
- Bulgu bazında severity ve hedef bazında `MAX_SEVERITY`
- 403/401/429 gibi non-2xx yanıtlar için uyarı (WAF/edge/auth wall olabilir)
- JSON rapor çıktısı
- Ham header'ları yazdırma

## Kurulum
```bash
git clone https://github.com/<username>/header-scout.git
cd header-scout
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

**İpucu:** `headerscout: command not found` görürsen `.venv` aktif değildir: `source .venv/bin/activate`

## Kullanım

### Tek hedef
```bash
headerscout example.com
headerscout https://example.com
```

### Modlar
```bash
# Hunter (varsayılan): FAIL/WARN odaklı + raporlanabilirlik notu
headerscout example.com

# Hardening: PASS/INFO dahil her şeyi göster
headerscout example.com --mode hardening
```

### Ham header'ları göster
```bash
headerscout example.com --show-headers
```

### JSON raporu yaz
```bash
headerscout example.com --json output.json
```

### Statü filtreleme
```bash
headerscout example.com --only FAIL,WARN
```

### Dosyadan çoklu hedef

`targets.txt` örneği:
- Boş satırlar atlanır
- `#` ile başlayan satırlar yorum kabul edilir
- Satır içi yorum desteklenir: `example.com # prod`
```
# production
example.com
https://www.cloudflare.com # CDN
http://neverssl.com
```

Çalıştır:
```bash
headerscout --file targets.txt
```

### Hızlı triage için summary-only
```bash
headerscout --file targets.txt --summary-only
```

Her hedef için MAX severity ve STATUS kodu da gösterilir.

## Örnek Çıktı

### Hardening modu (her şey):
```
Target: https://eksisozluk.com/
Summary: PASS=7 WARN=1 FAIL=1 INFO=0 | STATUS=403 | MAX_SEVERITY=MEDIUM
------------------------------------------------------------------------
Warning: Non-2xx response (403). Headers may belong to an auth wall, 
rate-limit, or WAF block page and may not represent the real application response.
------------------------------------------------------------------------

[WARN][LOW] HSTS: HSTS present but includeSubDomains is not set (may be acceptable).
       Recommendation: Consider adding includeSubDomains if you control and serve 
       all subdomains over HTTPS.

[FAIL][MEDIUM] CSP: Missing Content-Security-Policy header.
       Recommendation: Add a Content-Security-Policy to reduce XSS impact 
       (start with a restrictive policy and iterate).

[PASS][LOW] X-Frame-Options: X-Frame-Options set to a safe value: SAMEORIGIN
...
```

### Hunter modu (varsayılan, FAIL/WARN odaklı):
```
[FAIL][MEDIUM] CSP: Missing Content-Security-Policy header.
       Recommendation: Add a Content-Security-Policy to reduce XSS impact 
       (start with a restrictive policy and iterate).
       Reportability: Often rejected unless paired with XSS; sometimes 
       accepted as hardening.
```

## Notlar ve Kısıtlar

- Kontroller heuristic tabanlıdır; her header her uygulama için zorunlu değildir.
- "Header eksik" sonucu tek başına bug bounty'de kabul edilmeyebilir.
- Özellikle CSP eksikliği çoğu programda "XSS yoksa" informational sayılır.
- 401/403/429 gibi non-2xx yanıtlar WAF/edge/auth wall olabilir; header'lar gerçek uygulamayı temsil etmeyebilir.

## Katkıda Bulunma

Pull request'ler kabul edilir. Büyük değişiklikler için önce issue açmanızı öneririm.

## Lisans

MIT License. Detaylar için `LICENSE` dosyasına bakın.
