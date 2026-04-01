import sys
import warnings

# Deprecation warning for Python 3.8/3.9
if sys.version_info < (3, 10):
    warnings.warn(
        "Support for Python 3.8 and 3.9 is deprecated and will be removed in v2.0.0 (coming soon). "
        "Please upgrade to Python 3.10 or higher. "
        "See: https://github.com/Mastercard/oauth1-signer-python#compatibility",
        DeprecationWarning,
        stacklevel=2
    )
