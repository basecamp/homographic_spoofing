# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Sanitize uppercase and mixed-case confusable IDN domains.
- Scan each domain label independently for script confusables.
- Anchor allowed-TLD matching to whole TLD labels.
- Disallow the characters Chromium removes as quotation-mark and letter look-alikes: U+0138 (kra), U+02BB (turned comma), U+02BC (apostrophe) and U+02EC (voicing).
- Renamed `MOZILLA_DISALLOWED_CHARACTERS` to `DISALLOWED_CHARACTERS`, since the list now combines Mozilla's and Chromium's removals.
- Apply the mixed-script, mixed-digit, digit and script-specific rules to each subdomain label separately rather than to the whole subdomain chain.
- Flag a label that is only a CJK ideograph that looks like Latin or punctuation, such as `一` in `a.一.example.com`.
- Sanitize an email address only within the part each detection came from, so a benign mailbox that equals a spoofed domain label is left intact.
- Check the mailbox and each route domain of an address with an obsolete route separately instead of flagging the route itself.

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
