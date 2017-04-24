import ramrod
from stix.core import STIXPackage
from stix.utils.parser import UnsupportedVersionError
from stix.extensions.marking import ais  # Needed to support AIS Markings
from stix.extensions.marking.tlp import TLPMarkingStructure


class StixPackageContainer(object):
    """Container used to hold a STIX package and metadata about its source."""

    def __init__(self, package=None, source_metadata=None):
        self.package = package
        if isinstance(source_metadata, dict):
            self.source_metadata = source_metadata
        else:
            self.source_metadata = dict()

    @classmethod
    def from_file(cls, file_io):
        """Create a StixPackageContainer with a package from file I/O."""
        try:
            package = STIXPackage.from_xml(file_io)

        except UnsupportedVersionError:
            updated = ramrod.update(file_io, to_='1.1.1')
            document = updated.document.as_stringio()
            try:
                package = STIXPackage.from_xml(document)
            except Exception:
                package = None

        except Exception:
            package = None

        if package is not None:
            return cls(package)
        else:
            return None

    def id(self):
        return self.package.id_

    def title(self, default=''):
        """Retrieves the STIX package title (str) from the header."""
        if self.package.stix_header and self.package.stix_header.title:
            return self.package.stix_header.title.encode('utf-8')
        else:
            return default

    def description(self, default=''):
        """Retrieves the STIX package description (str) from the header."""
        if self.package.stix_header and self.package.stix_header.description:
            return self.package.stix_header.description.value.encode('utf-8')
        else:
            return default

    def tlp(self, default='AMBER'):
        """Retrieves the STIX package TLP (str) from the header."""
        if self.package.stix_header:
            handling = self.package.stix_header.handling
            if handling and handling.markings:
                for marking_spec in handling.markings:
                    for marking_struct in marking_spec.marking_structures:
                        if isinstance(marking_struct, TLPMarkingStructure):
                            return marking_struct.color
        return default

    def source_metadata(self, field):
        """Return a field from the source_metadata dict (or None)."""
        return self.source_metadata.get(field)
