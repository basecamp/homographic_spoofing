# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Sanitize uppercase and mixed-case confusable IDN domains.
- Scan each domain label independently for script confusables.
- Anchor allowed-TLD matching to whole TLD labels.

### Security

- Pin GitHub Actions to commit SHAs and add an actionlint + zizmor audit job.

## [0.1.2] - 2025-07-22

### Added

- `csv` gem dependency (extracted from the standard library in Ruby 3.4).

### Changed

- Regenerated the allowed-IDN-character and digit tables.
- Renamed `MOZZILLA_DISALLOWED_CHARACTERS` to `MOZILLA_DISALLOWED_CHARACTERS`.

## [0.1.1] - 2024-06-20

### Added

- `homepage_uri` and `source_code_uri` gem metadata.

## [0.1.0] - 2024-06-20

### Added

- Initial release: detect and sanitize homographic spoofing attacks in URLs and
  email addresses.

[Unreleased]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basecamp/homographic_spoofing/releases/tag/v0.1.0
