# Changelog

## [1.10.0] - 2026-10-XX (TODO UPDATE)

### Added
- Support for Python 3.13.

### Deprecated
- Python 3.8, 3.9 and 3.10 have reached end-of-life. They remain usable with the library, but will not be actively supported going forward.
- Importing the package on Python 3.8, 3.9 or 3.10 emits a `DeprecationWarning` (previously only on 3.8 and 3.9).

### Changed
- Declared `python_requires=">=3.8,<3.14"`, added the 3.13 classifier and removed deprecated `tests_require` in `setup.py`.

### Security
- Python 3.10+ requires `requests>=2.33.0` (unchanged from 1.9.2), which fixes [CVE-2026-25645](https://github.com/advisories/GHSA-gc5v-m9x4-r6x2). This library does not call the affected `extract_zipped_paths()` function, so Python 3.8 and 3.9, which cannot use `requests>=2.33.0`, remain on `requests>=2.31.0,<2.32.5` and are not affected in standard use.

## [1.9.2] - 2026-04-01

### Deprecated
- Python 3.8 and 3.9 support, will be removed in v2.0.0. Import-time deprecation warning emitted on 3.8/3.9.

### Added
- Support for Python 3.10, 3.11, 3.12.
- Support for selecting the OAuth signature method via `SignatureMethod`, including `RSA-PSS-SHA256`. `RSA-SHA256` remains the default when `signature_method` is not provided.

### Changed
- Declared `python_requires=">=3.8,<3.13"`.
