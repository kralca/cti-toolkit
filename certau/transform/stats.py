from .text import StixTextTransform


class StixStatsTransform(StixTextTransform):
    """Generate summary statistics for a STIX package.

    Prints a count of the number of observables for each object type
    contained in the package.

    Args:
        package: the STIX package to process
        separator: a string separator used in the text output
        include_header: a boolean value that indicates whether or not header
            information should be included in the text output
        header_prefix: a string prepended to header lines in the output
        pretty_text: a boolean that indicates whether or not the text
            should be made pretty by aligning the columns in
            the text output
    """

    LINE = '++++++++++++++++++++++++++++++++++++++++'

    def __init__(self, package, separator='\t', include_header=True,
                 header_prefix='', pretty_text=True):
        super(StixStatsTransform, self).__init__(
            package, separator, include_header, header_prefix,
        )
        self._pretty_text = pretty_text

    def _package_stats(self):
        elements = {
            'campaigns': set(),
            'courses_of_action': set(),
            'exploit_targets': set(),
            'indicators': set(),
            'kill_chains': set(),
            'observables': set(),
            'threat_actors': set(),
            'ttps': set(),
        }

        def _process_indicator(indicator):
            """Count all indicators except compositions."""
            if indicator.composite_indicator_expression:
                for i in indicator.composite_indicator_expression:
                    _process_indicator(i)
            else:
                if indicator.id_:
                    elements['indicators'].add(indicator.id_)
                if len(indicator.observables):
                    for o in indicator.observables:
                        _process_observable(o)

        def _process_observable(observable):
            """Count all observables except compositions."""
            if observable.observable_composition:
                for o in observable.observable_composition.observables:
                    _process_observable(o)
            else:
                if observable.id_:
                    elements['observables'].add(observable)

        for key in elements.keys():
            if key == 'kill_chains':
                list_ = getattr(self._package.ttps, key)
            else:
                list_ = getattr(self._package, key)

            self._logger.debug(list_)
            if list_:
                for v in list_:
                    if key == 'indicators':
                        _process_indicator(v)
                    elif key == 'observables':
                        _process_observable(v)
                    else:
                        if v.id_:
                            elements[key].add(v.id_)

        return elements

    def text_for_package_stats(self):
        labels = {
            'campaigns': 'Campaigns',
            'courses_of_action': 'Courses of action',
            'exploit_targets': 'Exploit targets',
            'indicators': 'Indicators',
            'kill_chains': 'Kill chains',
            'observables': 'Observables',
            'threat_actors': 'Threat actors',
            'ttps': 'TTPs',
        }
        text = ''
        elements = self._package_stats()
        for e in sorted(elements.keys()):
            if len(elements[e]):
                if self._pretty_text:
                    text += '{0:<35} {1:>4}\n'.format(
                        labels[e] + ':',
                        len(elements[e]),
                    )
                else:
                    text += self.join([labels[e], len(elements[e])]) + '\n'
        return text

    def header(self):
        header = self._header_prefix + self.LINE + '\n'
        header += self._header_prefix + 'Summary statistics:'

        title = self.package_title()
        if title:
            header += ' ' + title

        tlp = self.package_tlp()
        if tlp:
            header += ' (' + tlp + ')'

        header += '\n' + self._header_prefix + self.LINE + '\n'
        header += '\n' + self.text_for_package_stats() + '\n'
        return header

    def text_for_object_type(self, object_type):
        if object_type in self._observables:
            count = len(self._observables[object_type])
        else:
            count = 0
        if self._pretty_text:
            text = '{0:<35} {1:>4}\n'.format(
                object_type + ' observables:',
                count,
            )
        else:
            text = self.join([object_type, count]) + '\n'
        return text
