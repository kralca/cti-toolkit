from __future__ import absolute_import

from elasticsearch import Elasticsearch

from .base import StixTransform


class StixElasticsearchTransform(StixTransform):

    COPY_FIELDS = [
        'timestamp',
        'title',
        'description',
    ]

    def __init__(self, package, elasticsearch, index='ctitoolkit'):
        super(StixElasticsearchTransform, self).__init__(package)
        #self._es = Elasticsearch(['elastic'])
        self._es = Elasticsearch([{'host': '10.20.34.40', 'port': 9200}])
        print index


        self._index = index

    def _fix_indicator_types(self, doc):
        indicator_types = doc.get('indicator_types')
        if indicator_types is not None:
            new_list = []
            for type_ in indicator_types:
                new_list.append(type_['value'])
            doc['indicator_types'] = new_list

    def _fix_indicated_ttps(self, doc):
        indicated_ttps = doc.get('indicated_ttps')
        if indicated_ttps is not None:
            new_list = []
            for ttp in indicated_ttps:
                if 'title' in ttp['ttp']:
                    new_list.append(ttp['ttp']['title'])
                else:
                    new_list.append(ttp['ttp']['id'])
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
        self._reconstruct_indicators()
        for id_, indicator in self._package_parts['indicators'].iteritems():
            doc = indicator.to_dict()
            self._fix_indicator_types(doc)
            self._fix_indicated_ttps(doc)
            self._fix_observables(doc)

            del doc['id']

            result = self._es.index(
                index=self._index,
                id=id_,
                body=doc,
                doc_type='stix',
            )
            print result
