from StringIO import StringIO

from certau.source import StixSource
from certau.lib.stix import StixPackageContainer


class TaxiiPollResponseSource(StixSource):
    """Return STIX packages obtained from a TAXII poll response.

    Args:
        poll_response: a libtaxii PollResponse message
        poll_url: the URL used for sending the poll request
        collection: the collection that was polled
    """

    def __init__(self, poll_response, poll_url):
        super(TaxiiPollResponseSource, self).__init__()
        self.poll_response = poll_response
        self.poll_url = poll_url
        self.collection = poll_response.collection_name
        self.packages = self.all_packages()
        self.description = (
            "{} STIX packages from TAXII poll response ({}{}{})".format(
                len(self.packages),
                "collection: '{}'; ".format(self.collection),
                "poll URL: '{}'; ".format(poll_url),
                "end time: '{}'".format(
                    poll_response.inclusive_end_timestamp_label.isoformat(' ')
                )
            )
        )

    def next_stix_package(self):
        if self.index < len(self.poll_response.content_blocks):
            content_block = self.poll_response.content_blocks[self.index]
            package_io = StringIO(content_block.content)
            package = StixPackageContainer.from_file(package_io)
            package.source_metadata['taxii_poll_url'] = self.poll_url
            package.source_metadata['taxii_collection'] = self.collection
            if content_block.timestamp_label:
                taxii_timestamp = content_block.timestamp_label
                package.source_metadata['taxii_timestamp'] = taxii_timestamp
            self.index += 1
        else:
            package = None
        return package
