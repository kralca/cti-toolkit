"""Test setup."""
import pytest
import stix
import StringIO

import certau.source

@pytest.fixture(scope="module")
def source():
    """Create a 'package' fixture.

    If you include 'package' as a test argument, you have access to a
    pre-loaded STIX package, ready to transform.
    """
    return certau.source.FileSource(['tests/CA-TEST-STIX.xml'])
    # with open('tests/CA-TEST-STIX.xml', 'rb') as stix_f:
    #     stix_io = StringIO.StringIO(stix_f.read())
    #     return stix.core.STIXPackage.from_xml(stix_io)
