# Changelog

## [1.9.2] - 2026-04-01

### Deprecated
- Python 3.8 and 3.9 support, will be removed in v2.0.0. Import-time deprecation warning emitted on 3.8/3.9.

### Added
- Support for Python 3.10, 3.11, 3.12.
- Support for selecting the OAuth signature method via `SignatureMethod`, including `RSA-PSS-SHA256`. `RSA-SHA256` remains the default when `signature_method` is not provided.

### Changed
- Declared `python_requires=">=3.8,<3.13"`.

## [2.0.0] - 2026-05-01 (Planned)

### Breaking Changes
- Minimum supported Python: 3.10 (dropped 3.8 and 3.9).
