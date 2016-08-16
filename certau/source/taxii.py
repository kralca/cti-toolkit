import logging
from StringIO import StringIO

from certau.source import StixSource
from certau.lib import SimpleTaxiiClient


class TaxiiSource(StixSource):
    """A simple interface to the libtaxii libraries for polling a TAXII server.

    The :py:class:`certau.client.SimpleTaxiiClient` class
    provides a simple interface for polling a collection on a TAXII server and
    returning the response. It supports SSL (certificate-based)
    authentication in addition to a username and password.

    Args:
        hostname: the name of the TAXII server
        path: the URL path for the collection
        collection: the collection on the TAXII server to poll
        use_ssl: use SSL when connecting to the TAXII server
        username: a username for password-based authentication
        password: a password for password-based authentication
        port: the port to connect to on the TAXII server
        key_file: a private key file for SSL certificate-based authentication
        cert_file: a certificate file for SSL certificate-based authentication
        begin_ts: a timestamp to describe the earliest content to be returned
                  by the TAXII server
        end_ts: a timestamp to describe the most recent content to be returned
                by the TAXII server
        subscription_id: a subscription ID to include with the poll request
        poll_url: a URL specifying the TAXII endpoing (use instead of hostname,
                  path, port and use_ssl)
        output_dir: a directory to store the TAXII poll response content
                    blocks in
    """

    def __init__(self, hostname, path, collection, use_ssl=False,
                 username=None, password=None, port=None, key_file=None,
                 cert_file=None, ca_file=None, begin_ts=None, end_ts=None,
                 subscription_id=None, poll_url=None, output_dir=None):
        super(TaxiiSource, self).__init__()

        self._logger = logging.getLogger()
        self._cb_index = 0

        taxii_client = SimpleTaxiiClient(
            hostname=hostname,
            path=path,
            use_ssl=use_ssl,
            port=port,
            url=poll_url,
            username=username,
            password=password,
            key_file=key_file,
            cert_file=cert_file,
            ca_file=ca_file,
        )
        poll_response = taxii_client.send_poll_request(
            collection,
            subscription_id=subscription_id,
            begin_ts=begin_ts,
            end_ts=end_ts,
        )
        self._content_blocks = poll_response.content_blocks

        if output_dir:
            taxii_client.save_content_blocks(output_dir, poll_response)

    def next_stix_package(self):
        if self._cb_index < len(self._content_blocks):
            content_block = self._content_blocks[self._cb_index]
            package_io = StringIO(content_block.content)
            package = self.load_stix_package(package_io)
            self._cb_index += 1
        else:
            package = None
        return package
