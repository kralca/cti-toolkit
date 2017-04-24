import datetime
import os
import logging

from certau.source import StixSource
from certau.lib.stix import StixPackageContainer


class FileSource(StixSource):
    """Return STIX packages from a file or directory.

    Args:
        files: an array containing the names of one or more files or
            directories
        recurse: an optional boolean value (default False), which when set
            to True, will cause subdirectories to be searched recursively
    """

    def __init__(self, files, recurse=False):
        super(FileSource, self).__init__()
        self.files = []
        for file_ in files:
            self.add_file(file_, recurse)
        self.packages = []
        self.add_packages(files)

        # Set the description
        count = len(self.packages)
        self.description = (
            "{} STIX package{} from {} ({}{}{})".format(
                count,
                "s" if count > 1 else "",
                "{} '{}'".format(
                    "directory" if os.path.isdir(files[0]) else "file",
                    files[0],
                ) if len(files) == 1 else "various files",
                "recursion: true; " if recurse else "",
                "file prefix: '{}*'; ".format(
                    os.path.commonprefix(self.files)) if len(files) > 1 else '',
                "processed: '{}'".format(
                    datetime.datetime.now().isoformat(' '),
                )
            )
        )

    def add_file(self, file_, recurse):
        if os.path.isdir(file_):
            for dir_file in sorted(os.listdir(file_)):
                path = os.path.join(file_, dir_file)
                if os.path.isdir(path) and recurse:
                    self._add_file(path, recurse)
                elif os.path.isfile(path):
                    self.files.append(path)
        elif os.path.isfile(file_):
            self.files.append(file_)

    def add_packages(self, files):
        for file_ in files:
            package = StixPackageContainer.from_file(file_)
            if package is None:
                self._logger.info(
                    "skipping file '%s' - invalid XML/STIX" % file_
                )
                continue

            package.source_metadata['filename'] = os.path.basename(file_)
            self.packages.append(package)
