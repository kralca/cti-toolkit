import os
import logging
import sys

from StringIO import StringIO

from certau.source import StixSource
from certau.lib.stix import StixPackageContainer

import dateutil.parser
from libtaxii import get_message_from_http_response, VID_TAXII_XML_11
from libtaxii.messages_11 import PollRequest, PollResponse, MSG_POLL_RESPONSE
from libtaxii.messages_11 import generate_message_id
from libtaxii.clients import HttpClient
from libtaxii.scripts import TaxiiScript


class TaxiiPollResponseSource(StixSource):
    """Return STIX packages obtained from a TAXII poll response.

    Args:
        poll_response: a libtaxii PollResponse message
        poll_url: the URL used for sending the poll request
        collection: the collection that was polled
    """

    @classmethod
    def from_poll_response(cls, poll_response, poll_url):
        # super(TaxiiPollResponseSource, self).__init__()

        if not isinstance(poll_response, PollResponse):
            raise Exception('poll_response not a valid libtaxii PollResponse')

        # load content_blocks
        packages = []
        for content_block in poll_response.content_blocks:
            package_io = StringIO(content_block.content)
            package = StixPackageContainer.from_file(package_io)

            # Populate source metadata relating to the poll response
            package.source_metadata['taxii_poll_url'] = self.poll_url
            package.source_metadata['taxii_collection'] = self.collection
            if content_block.timestamp_label:
                taxii_timestamp = content_block.timestamp_label
                package.source_metadata['taxii_timestamp'] = taxii_timestamp

            packages.append(package)

        self.poll_response = poll_response
        self.poll_url = poll_url
        self.collection = poll_response.collection_name
        self.packages = packages
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

    def get_poll_response_end_timestamp(self):
        end_timestamp = self.poll_response.inclusive_end_timestamp_label
        return end_timestamp.isoformat() if end_timestamp else None

    # def save_content_blocks(self, directory):
    #     """Save poll response content blocks to given directory."""
    #     if os.path.exists(directory) and self.poll_response:
    #         taxii_script = TaxiiScript()
    #         taxii_script.write_cbs_from_poll_response_11(
    #             self.poll_response,
    #             directory,
    #         )
    #     elif not self.poll_response:
    #         raise Exception('no poll response, call send_poll_request() first')
    #     else:
    #         raise Exception('output directory for TAXII content blocks ({}) '
    #                         'does not exist'.format(directory))
