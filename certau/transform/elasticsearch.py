from __future__ import absolute_import

from elasticsearch import Elasticsearch

from .base import StixTransform

import sys


class ElasticsearchTransform(StixTransform):

    COPY_FIELDS = [
        'timestamp',
        'title',
        'description',
    ]

    def __init__(self, elasticsearchURL, elasticsearchPORT, index='ctitoolkit'):
        super(ElasticsearchTransform, self).__init__()
        self._es = Elasticsearch([{'host': elasticsearchURL, 'port': elasticsearchPORT}])


        self._index = index

    def _fix_indicator_types(self, doc):
        indicator_types = doc.get('indicator_types')
        if indicator_types is not None:
            new_list = []
            for type_ in indicator_types:
                if isinstance(type_,dict):
                    new_list.append(type_['value'])                
                elif isinstance(type_,str):
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
                doc['observables'] = [ observable ]

    def publish(self):
        #self._reconstruct_indicators()
        #self.process_indicators()
        for id_, indicator in self.elements['indicators'].iteritems():
            doc = indicator.to_dict()
            self._fix_indicated_ttps(doc, indicator)
            self._fix_indicator_types(doc)
            self._fix_observables(doc)
            tlp = self.get_tlp_from_indicator(id_, indicator)
            source_metadata = self.containers[id_].source_metadata
            doc['source_metadata'] = source_metadata
            doc['tlp'] = tlp

            del doc['id']
            try:
                result = self._es.index(
                    index=self._index,
                    id=id_,
                    body=doc,
                    doc_type='stix',
                )
                #print result
            except:
                print "WARNING"
                print sys.exc_info()
                

    def do_transform(self):
        return self.publish()

