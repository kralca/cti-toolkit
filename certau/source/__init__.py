"""Classes that provide a source of STIX packages.

These classes should implement the ``next_stix_package()`` method.
"""

from .base import StixSource
from .files import FileSource
from .taxii import TaxiiPollResponseSource
