from __future__ import absolute_import

import sys

from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk, parallel_bulk

from .base import StixTransform


class ElasticsearchTransform(StixTransform):

    COPY_FIELDS = [
        'timestamp',
        'title',
        'description',
    ]

    def __init__(self, elasticsearchURL, elasticsearchPORT,
                 index='ctitoolkit'):
        super(ElasticsearchTransform, self).__init__()
        self._es = Elasticsearch([{
            'host': elasticsearchURL,
            'port': elasticsearchPORT,
        }])
        self._index = index
        self._data = {}

    def _fix_indicator_types(self, doc):
        indicator_types = doc.get('indicator_types')
        if indicator_types is not None:
            new_list = []
            for type_ in indicator_types:
                if isinstance(type_, dict):
                    new_list.append(type_['value'])
                elif isinstance(type_, str):
                    new_list.append(type_)
            doc['indicator_types'] = new_list

    def _fix_indicated_ttps(self, doc, indicator):
        ttps = self.dereference_indicator_element(indicator, 'indicated_ttps')
        new_list = []
        for ttp_obj in ttps:
            ttp = ttp_obj.to_dict()
            if 'title' in ttp:
                new_list.append(ttp['title'])
            else:
                new_list.append(ttp['id'])
        if new_list:
            doc['indicated_ttps'] = new_list

    def _fix_observables(self, doc):
        observable = doc.get('observable')
        if observable is not None:
            del doc['observable']
            composition = observable.get('observable_composition')
            if composition is not None:
                doc['observables'] = composition.get('observables')
                doc['observable_composition_id'] = observable['id']
            else:
                doc['observables'] = [observable]

    def publish(self, bulk_fn):
        def generator():

            for id_, indicator in self.elements['indicators'].iteritems():
                doc = indicator.to_dict()
                self._fix_indicated_ttps(doc, indicator)
                self._fix_indicator_types(doc)
                self._fix_observables(doc)
                tlp = self.get_tlp_from_indicator(id_, indicator)
                source_metadata = self.containers[id_].source_metadata
                doc['source_metadata'] = source_metadata
                doc['tlp'] = tlp
                if ':' in id_:
                    doc['source_id'] = id_.split(':')[0]

                del doc['id']
                try:
                    yield {
                            '_index': self._index,
                            '_id': id_,
                            '_type': 'stix',
                            '_source': doc,
                            }
                except:
                    logger.error(sys.exc_info())

        for ok, result in bulk_fn(self._es, generator()):
            if not ok:
                logger.warning("A document failed: %s", str(result))

    def do_transform(self):
        return self.publish(parallel_bulk)
