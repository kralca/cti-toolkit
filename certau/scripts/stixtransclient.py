"""
This script supports transforming indicators (observables) from a STIX Package
into the Bro Intelligence Format. It can interact with a TAXII server to obtain
the STIX package(s), or a STIX package file can be supplied.
"""

import sys
import logging
import pkg_resources

import configargparse

from certau.lib.taxii import SimpleTaxiiClient
from certau.source import FileSource, TaxiiPollResponseSource
from certau.transform import CsvTransform, StatsTransform, SnortTransform
from certau.transform import BroIntelTransform, MispTransform


def get_arg_parser():
    """Create an argument parser with options used by this script."""
    # Determine arguments and get input file
    parser = configargparse.ArgumentParser(
        default_config_files=['/etc/ctitoolkit.conf', '~/.ctitoolkit'],
        description=("A utility to transform STIX package contents into other "
                     "formats."),
    )

    # Global options
    global_group = parser.add_argument_group('global arguments')
    global_group.add_argument(
        "-c", "--config",
        is_config_file=True,
        help="configuration file to use",
    )
    global_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="verbose output",
    )
    global_group.add_argument(
        "-d", "--debug",
        action="store_true",
        help="enable debug output",
    )
    global_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="suppress warnings - only errors will be displayed",
    )
    version = pkg_resources.require('cti-toolkit')[0].version
    global_group.add_argument(
        "-V", "--version",
        action="version",
        version="cti-toolkit {} by CERT Australia".format(version),
    )
    global_group.add_argument(
        "--aggregate",
        action="store_true",
        help="aggregate STIX packages before doing the transform",
    )

    # Source options
    source_group = parser.add_argument_group('input (source) options')
    source_ex_group = source_group.add_mutually_exclusive_group(
        required=True,
    )
    source_ex_group.add_argument(
        "--file",
        nargs="+",
        help="obtain STIX packages from supplied files or directories",
    )
    source_ex_group.add_argument(
        "--taxii",
        action="store_true",
        help="poll TAXII server to obtain STIX packages",
    )

    # Output (transform) options
    output_group = parser.add_argument_group('output (transform) options')
    output_group.add_argument(
        "-s", "--stats",
        action="store_true",
        help="display summary statistics for each STIX package",
    )
    output_group.add_argument(
        "-t", "--text",
        action="store_true",
        help="output observables in delimited text",
    )
    output_group.add_argument(
        "-b", "--bro",
        action="store_true",
        help="output observables in Bro intel framework format",
    )
    output_group.add_argument(
        "-m", "--misp",
        action="store_true",
        help="send output to a MISP server",
    )
    output_group.add_argument(
        "--snort",
        action="store_true",
        help="output observables in Snort rule format",
    )
    output_group.add_argument(
        "-x", "--xml-output",
        help=("output XML STIX packages (one per file) to the given directory "
              "(use with --taxii)"),
    )

    # File source options
    file_group = parser.add_argument_group(
        title='file input arguments (use with --file)',
    )
    file_group.add_argument(
        "-r", "--recurse",
        action="store_true",
        help="recurse subdirectories when processing files.",
    )

    # TAXII source options
    taxii_group = parser.add_argument_group(
        title='taxii input arguments (use with --taxii)',
    )
    taxii_group.add_argument(
        "--poll-url",
        help="the URL to send the TAXII poll request to"
    )
    taxii_group.add_argument(
        "--hostname",
        help="hostname of TAXII server (Deprecated. Use --poll-url instead)",
    )
    taxii_group.add_argument(
        "--port",
        help="port of TAXII server (Deprecated. Use --poll-url instead)",
    )
    taxii_group.add_argument(
        "--ca_file",
        help="File containing CA certs of TAXII server",
    )
    taxii_group.add_argument(
        "--username",
        help="username for TAXII authentication",
    )
    taxii_group.add_argument(
        "--password",
        help="password for TAXII authentication",
    )
    taxii_group.add_argument(
        "--ssl",
        action="store_true",
        help=("use SSL to connect to TAXII server "
              "(Deprecated. Use --poll-url instead)"),
    )
    taxii_group.add_argument(
        "--key",
        help="file containing PEM key for TAXII SSL authentication",
    )
    taxii_group.add_argument(
        "--cert",
        help="file containing PEM certificate for TAXII SSL authentication",
    )
    taxii_group.add_argument(
        "--path",
        help=("path on TAXII server for polling "
              "(Deprecated. Use --poll-url instead)"),
    )
    taxii_group.add_argument(
        "--collection",
        help="TAXII collection to poll",
    )
    taxii_group.add_argument(
        "--begin-timestamp",
        help=("TAXII poll request begin timestamp (format: "
              "YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm)"),
    )
    taxii_group.add_argument(
        "--end-timestamp",
        help=("TAXII poll request end timestamp (format: "
              "YYYY-MM-DDTHH:MM:SS.ssssss+/-hh:mm)"),
    )
    taxii_group.add_argument(
        "--subscription-id",
        help="a subscription ID for the poll request",
    )

    # Miscellaneous output options
    other_group = parser.add_argument_group(
        title='other output options',
    )
    other_group.add_argument(
        "-f", "--field-separator",
        default='|',
        help="field delimiter character/string to use in text output",
    )
    other_group.add_argument(
        "--header",
        action="store_true",
        help=("include header in output (for transforms which don't include "
              "a header by default)"),
    )
    other_group.add_argument(
        "--no-header",
        action="store_true",
        help=("disable header in output (for transforms which include a "
              "header by default)"),
    )
    other_group.add_argument(
        "--title",
        help="title for package (if not included in STIX file)",
    )
    other_group.add_argument(
        "--source",
        help="source of indicators - e.g. Hailataxii, CERT-AU",
    )
    other_group.add_argument(
        "--base-url",
        help="base URL for indicator source - use with --bro or --misp",
    )

    # options for the Bro Intel transform
    bro_group = parser.add_argument_group(
        title='bro intel format output options (use with --bro)'
    )
    bro_group.add_argument(
        "--bro-no-notice",
        action="store_true",
        help="suppress Bro intel notice framework messages",
    )

    # options for the Snort transform
    snort_group = parser.add_argument_group(
        title='snort output arguments (use with --snort)',
    )
    snort_group.add_argument(
        "--snort-initial-sid",
        default=5500000,
        help="The initial Snort IDs to begin from (default: 5500000)",
    )
    snort_group.add_argument(
        "--snort-rule-revision",
        default=1,
        help="The revision of the Snort rule (default: 1)",
    )
    snort_group.add_argument(
        "--snort-rule-action",
        choices=["alert", "log", "pass", "activate", "dynamic",
                 "drop", "reject", "sdrop"],
        default="alert",
        help=("Change all Snort rules generated to "
              "[alert|log|pass|activate|dynamic|drop|reject|sdrop]"),
    )

    # options for the MISP transform
    misp_group = parser.add_argument_group(
        title='misp output arguments (use with --misp)',
    )
    misp_group.add_argument(
        "--misp-url",
        help="URL of MISP server",
    )
    misp_group.add_argument(
        "--misp-key",
        help="token for accessing MISP instance",
    )
    misp_group.add_argument(
        "--misp-distribution",
        default=0,
        type=int,
        help="MISP distribution group - default: 0 (your organisation only)",
    )
    misp_group.add_argument(
        "--misp-threat",
        default=4,
        type=int,
        help="MISP threat level - default: 4 (undefined)",
    )
    misp_group.add_argument(
        "--misp-analysis",
        default=0,
        type=int,
        help="MISP analysis phase - default: 0 (initial)",
    )
    misp_group.add_argument(
        "--misp-info",
        help="MISP event description",
    )
    misp_group.add_argument(
        "--misp-published",
        action="store_true",
        help="set MISP published state to True",
    )
    return parser


def main():
    parser = get_arg_parser()
    options = parser.parse_args()

    logger = logging.getLogger(__name__)
    if options.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif options.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    elif options.quiet:
        logging.basicConfig(stream=sys.stderr, level=logging.ERROR)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    logger.info("logging enabled")

    # Process the transform (output) options before processing inputs (which
    # may be resource intensive)
    transforms = []
    if options.stats:
        transforms.append(StatsTransform(
            output=sys.stdout,
            include_header=(not options.no_header)
        ))

    if options.text:
        transforms.append(CsvTransform(
            output=sys.stdout,
            include_header=(not options.no_header),
            separator=options.field_separator,
        ))

    if options.bro:
        transforms.append(BroIntelTransform(
            output=sys.stdout,
            include_header=options.header,
            do_notice=(not options.bro_no_notice),
        ))

    if options.misp:
        transforms.append(MispTransform(
            misp=MispTransform.get_misp_object(
                misp_url=options.misp_url,
                misp_key=options.misp_key,
            ),
            distribution=options.misp_distribution,
            threat_level=options.misp_threat,
            analysis=options.misp_analysis,
            information=options.misp_info,
            published=options.misp_published,
        ))

    if options.snort:
        transforms.append(SnortTransform(
            output=sys.stdout,
            snort_initial_sid=options.snort_initial_sid,
            snort_rule_revision=options.snort_rule_revision,
            snort_rule_action=options.snort_rule_action,
        ))

    if options.xml_output and not options.taxii:
        # XML output option will be ignored if source is not TAXII
        logger.warning('--xml-output only supported for TAXII inputs')

    # Need at least one transform
    if not transforms and not options.xml_output:
        logger.error('no transform (output) option provided')
        return

    # Collect data from source
    if options.taxii:
        logger.info("Processing a TAXII poll request/response")
        taxii_client = SimpleTaxiiClient(
            username=options.username,
            password=options.password,
            key_file=options.key,
            cert_file=options.cert,
            ca_file=options.ca_file,
        )

        # Parse begin and end timestamp datetime strings if provided
        if options.begin_timestamp:
            begin_timestamp = dateutil.parser.parse(options.begin_timestamp)
        else:
            begin_timestamp = None

        if options.end_timestamp:
            end_timestamp = dateutil.parser.parse(options.end_timestamp)
        else:
            end_timestamp = None

        # Create the poll request message
        poll_request = taxii_client.create_poll_request(
            collection=options.collection,
            subscription_id=options.subscription_id,
            begin_timestamp=begin_timestamp,
            end_timestamp=end_timestamp,
        )

        # Build the poll URL if it wasn't provided
        if not options.poll_url:
            scheme = 'https' if options.ssl else 'http'
            netloc = options.hostname
            if options.port:
                netloc += ':{}'.format(options.port)
            url_parts = [scheme, netloc, options.path, '', '', '']
            poll_url = urlparse.urlunparse(url_parts)
        else:
            poll_url = options.poll_url

        # Send the poll request
        poll_response = taxii_client.send_poll_request(poll_request, poll_url)
        source = TaxiiPollResponseSource(poll_response, poll_url)

        # Process the output
        if options.xml_output:
            logger.debug("Writing XML to %s", options.xml_output)
            SimpleTaxiiClient.save_content_blocks(poll_response,
                                                  options.xml_output)

        logger.info("Processing TAXII content blocks")
    else:
        logger.info("Processing file input")
        source = FileSource(options.file, options.recurse)

    for transform in transforms:
        transform.process_source(source, options.aggregate)


if __name__ == '__main__':
    main()
