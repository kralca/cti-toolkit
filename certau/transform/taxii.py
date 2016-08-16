from certau.transform import StixTransform
from certau.lib import SimpleTaxiiClient


class StixTaxiiTransform(StixTransform):
    """Description goes here.
    """

    def __init__(self, package, taxii_client, collection, marking=None):
        super(StixTaxiiTransform, self).__init__(package)
        self._taxii_client = taxii_client
        self._collection = collection

        # Optionally add a Marking to the STIX package header.
        if marking:
            self._package.handling.add_marking(marking)

    def publish(self):
        self._taxii_client.send_inbox_message(
            collection=self._collection,
            stix_package=self._package,
        )
