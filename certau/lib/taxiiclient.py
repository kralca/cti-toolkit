import os
import logging
import urlparse

from libtaxii import get_message_from_http_response
from libtaxii import MSG_INBOX_MESSAGE, MSG_POLL_RESPONSE
from libtaxii import CB_STIX_XML_111, VID_TAXII_XML_11
from libtaxii.messages_11 import ContentBinding, ContentBlock, InboxMessage
from libtaxii.messages_11 import PollRequest, generate_message_id
from libtaxii.clients import HttpClient
from libtaxii.scripts import TaxiiScript


class SimpleTaxiiClient(HttpClient):
    """A simple interface for interacting with a TAXII server.

    The :py:class:`certau.lib.SimpleTaxiiClient` class
    provides a simple mechanism for either polling a collection
    on a TAXII server or sending a STIX package to a TAXII inbox.
    It supports SSL (certificate-based)
    authentication in addition to a username and password.

    Args:
        hostname: the name of the TAXII server
        path: the URL path for the collection
        use_ssl: use SSL when connecting to the TAXII server
        port: the port to connect to on the TAXII server
        url: a URL specifying the TAXII endpoint (instead of hostname, path,
             port, and use_ssl)
        username: a username for password-based authentication
        password: a password for password-based authentication
        key_file: a private key file for SSL certificate-based authentication
        cert_file: a certificate file for SSL certificate-based authentication
    """

    def __init__(self, hostname=None, path=None, use_ssl=False, port=None,
                 url=None, username=None, password=None, key_file=None,
                 cert_file=None, ca_file=None):
        super(SimpleTaxiiClient, self).__init__()

        self._logger = logging.getLogger()

        # Must get at least a hostname and path or a url
        if url:
            if hostname and path:
                self._logger.warning("using URL instead of hostname and path")

            # Extract hostname, path, use_ssl and port
            parsed_url = urlparse.urlparse(url)
            self._hostname = parsed_url.hostname
            self._port = parsed_url.port
            self._path = parsed_url.path
            self._use_ssl = (parsed_url.scheme == 'https')

        elif hostname and path:
            self._hostname = hostname
            self._port = port
            self._path = path
            self._use_ssl = use_ssl

        else:
            raise Exception('need either url or hostname and path')

        self.set_use_https(self._use_ssl)

        if self._use_ssl and ca_file:
            self._logger.debug("SSL - server verification using file (%s)",
                               ca_file)
            self.set_verify_server(verify_server=True, ca_file=ca_file)

        if self._use_ssl and key_file and cert_file and username and password:
            self._logger.debug(
                "AUTH - using certificate (%s) and user credentials (%s:%s)",
                cert_file, username, '*' * len(password),
            )
            self.set_auth_type(HttpClient.AUTH_CERT_BASIC)
            self.set_auth_credentials({
                'key_file': key_file,
                'cert_file': cert_file,
                'username': username,
                'password': password,
            })
        elif self._use_ssl and key_file and cert_file:
            self._logger.debug("AUTH - using certificate (%s)", cert_file)
            self.set_auth_type(HttpClient.AUTH_CERT)
            self.set_auth_credentials({
                'key_file': key_file,
                'cert_file': cert_file,
            })
        elif username and password:
            self._logger.debug(
                "AUTH - using user credentials (%s:%s)",
                username, '*' * len(password),
            )
            self.set_auth_type(HttpClient.AUTH_BASIC)
            self.set_auth_credentials({
                'username': username,
                'password': password,
            })
        else:
            self._logger.debug(
                "AUTH - using no certificate or user credentials",
            )
            self.set_auth_type(HttpClient.AUTH_NONE)

        # Set the index and the content blocks
        self._cb_index = 0
        self._poll_response = None

    def send_poll_request(self, collection, subscription_id=None,
                          begin_ts=None, end_ts=None, poll_parameters=None):
        """Send a TAXII poll request message to the server."""
        if not subscription_id and not poll_parameters:
            # Set minimal poll parameters
            poll_parameters = PollRequest.PollParameters()

        poll_request = PollRequest(
            message_id=generate_message_id(),
            collection_name=collection,
            exclusive_begin_timestamp_label=begin_ts,
            inclusive_end_timestamp_label=end_ts,
            subscription_id=subscription_id,
            poll_parameters=poll_parameters,
        )

        self._logger.debug('sending TAXII poll request')
        return self.send_request(poll_request, MSG_POLL_RESPONSE)

    def send_inbox_message(self, collection, stix_package):
        content_block = ContentBlock(
            content_binding=ContentBinding(CB_STIX_XML_111),
            content=stix_package.to_xml(),
        )
        inbox_message = InboxMessage(
            message_id=generate_message_id(),
            content_blocks=[content_block],
        )
        inbox_message.destination_collection_names.append(collection)

        self._logger.debug('sending TAXII inbox message')
        return self.send_request(inbox_message, MSG_INBOX_MESSAGE)

    def send_request(self, request, expected_response_type):
        """Send the TAXII request message to the server."""
        http_response = self.call_taxii_service2(
            host=self._hostname,
            path=self._path,
            message_binding=VID_TAXII_XML_11,
            post_data=request.to_xml(),
            port=self._port,
        )
        self._logger.debug("HTTP/TAXII response received (%s)",
                           http_response.__class__.__name__)

        response = get_message_from_http_response(http_response,
                                                  request.message_id)

        if response.message_type != expected_response_type:
            raise Exception('TAXII response not of expected type ({})'.format(
                            expected_response_type))

        return response

    @staticmethod
    def save_content_blocks(directory, poll_response):
        """Save poll response content blocks to given directory."""
        if not os.path.isdir(directory):
            raise Exception('output directory for TAXII content blocks ({}) '
                            'does not exist'.format(directory))
        if not poll_response:
            raise Exception('no poll response, call send_poll_request() first')

        taxii_script = TaxiiScript()
        taxii_script.write_cbs_from_poll_response_11(poll_response, directory)
