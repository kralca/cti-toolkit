import logging


class StixSource(object):
    """A base class for sources of STIX packages."""

    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self.description = ''
        self.packages = []
        self.reset()

    def reset(self):
        self.index = 0

    def all_packages(self):
        if self.packages:
            return self.packages
        else:
            self.reset()
            packages = []
            while True:
                package = self.next_stix_package()
                if package is None:
                    break
                packages.append(package)
            return packages

    def next_stix_package(self):
        """Return the next STIX package available from the source (or None)."""
        raise NotImplementedError
