import sys
import warnings

# Deprecation warning for Python 3.8/3.9/3.10
if sys.version_info < (3, 11):
    warnings.warn(
        "Python 3.8, 3.9 and 3.10 have reached EOL and we will not be providing ongoing support for these versions. "
        "Please upgrade to Python 3.11 or higher. "
        "See: https://github.com/Mastercard/oauth1-signer-python#compatibility",
        DeprecationWarning,
        stacklevel=2
    )
