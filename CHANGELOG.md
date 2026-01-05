# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Context-aware severity (`LOW / MEDIUM / HIGH`) and per-target `MAX_SEVERITY`
- `--mode hunter|hardening`:
  - `hunter` (default) focuses on FAIL/WARN and prints reportability hints
  - `hardening` prints everything (PASS/INFO included)
- Reportability hints (hunter mode) to reduce "informational-only" bug bounty reports
- Non-2xx response warning (e.g., 401/403/429) indicating headers may come from WAF/edge/auth walls
- Multi-target scanning via `--file` with support for `#` comments and inline comments
- `--summary-only` for one-line-per-target triage output (includes MAX severity and status code)
- JSON output enhancements: includes severity, reportability, and context metadata per report

### Changed
- CLI help text and descriptions updated for triage-oriented workflow
- Output formatting improved: status code and max severity included in the summary line

### Fixed
- Various runtime `NameError` issues in scanner output fields by standardizing severity naming and triage computation

---

# Değişiklik Kaydı (Türkçe)

Bu dosyada projedeki önemli değişiklikler listelenir.

Biçim [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) yaklaşımına dayanır ve sürümleme [Semantic Versioning](https://semver.org/spec/v2.0.0.html) ile uyumludur.

## [Unreleased]

### Eklendi
- Context-aware severity (`LOW / MEDIUM / HIGH`) ve hedef başına `MAX_SEVERITY`
- `--mode hunter|hardening`:
  - `hunter` (varsayılan) FAIL/WARN odaklı ve raporlanabilirlik notları içerir
  - `hardening` PASS/INFO dahil her şeyi gösterir
- Hunter modunda "reportability" notları (boş/triage'da reddedilecek raporları azaltmak için)
- Non-2xx yanıt uyarısı (örn. 401/403/429): header'lar WAF/edge/auth wall'dan geliyor olabilir
- `--file` ile çoklu hedef tarama, `#` yorum satırları ve satır içi yorum desteği
- `--summary-only`: hedef başına tek satır triage çıktısı (MAX severity ve status code dahil)
- JSON çıktısı zenginleştirmeleri: rapora severity, reportability, context metadata alanları eklendi

### Değiştirildi
- CLI help metinleri triage odaklı akışa göre güncellendi
- Çıktı formatı iyileştirildi: summary satırına status code ve max severity eklendi

### Düzeltildi
- Scanner tarafında alan isimleri standartlaştırılarak (severity) çeşitli `NameError` çalışma zamanı hataları giderildi
