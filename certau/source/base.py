import logging


class StixSource(object):
    """A base class for sources of STIX packages."""

    def __init__(self, packages=None, description=None):
        self._logger = logging.getLogger(__name__)
        self.packages = packages
        self.description = description
