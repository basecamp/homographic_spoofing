# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-11-26

### Fixed

- Check the label directly under a wildcard public suffix, such as `раураӏ` in `раураӏ.mm` or `раураӏ.sch.uk`, and every label below it. These names were skipped entirely.
- Treat U+04AF (`ү`, Cyrillic straight u) as a Latin `y` look-alike, so whole-Cyrillic labels such as `үеѕ` are flagged like `уеѕ`.
- Stop allowing whole-Cyrillic look-alike labels under `pyc`, which is not a TLD.
- Flag a nonspacing mark that appears twice in one run of marks once the label is decomposed, such as `é` followed by U+0301, and flag a run of more than 30 marks.
- Ignore private public-suffix entries when splitting a domain, so names such as `раураӏ.compute.amazonaws.com` are checked like any other name.

## [0.2.0] - 2026-10-20

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

[Unreleased]: https://github.com/basecamp/homographic_spoofing/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/basecamp/homographic_spoofing/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/basecamp/homographic_spoofing/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basecamp/homographic_spoofing/releases/tag/v0.1.0
