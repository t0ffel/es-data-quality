# -*- coding: utf-8 -*-
import logging

from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch

from time_util import dt_to_ts

logging.basicConfig()
ElastReporter_logger = logging.getLogger('es_pipelines_reporter')


def new_get_event_ts(ts_field):
    """ Constructs a lambda that may be called to extract the timestamp field
    from a given event.

    :returns: A callable function that takes an event and outputs that event's
    timestamp field.
    """
    return lambda event: lookup_es_key(event[0], ts_field)


def _find_es_dict_by_key(lookup_dict, term):
    """ Performs iterative dictionary search based upon the following conditions:

    1. Subkeys may either appear behind a full stop (.) or at one lookup_dict level lower in the tree.
    2. No wildcards exist within the provided ES search terms (these are treated as string literals)

    This is necessary to get around inconsistencies in ES data.

    For example:
      {'ad.account_name': 'bob'}
    Or:
      {'csp_report': {'blocked_uri': 'bob.com'}}
    And even:
       {'juniper_duo.geoip': {'country_name': 'Democratic People's Republic of Korea'}}

    We want a search term of form "key.subkey.subsubkey" to match in all cases.
    :returns: A tuple with the first element being the dict that contains the key and the second
    element which is the last subkey used to access the target specified by the term. None is
    returned for both if the key can not be found.
    """
    if term in lookup_dict:
        return lookup_dict, term

    # If the term does not match immediately, perform iterative lookup:
    # 1. Split the search term into tokens
    # 2. Recurrently concatenate these together to traverse deeper into the dictionary,
    #    clearing the subkey at every successful lookup.
    #
    # This greedy approach is correct because subkeys must always appear in order,
    # preferring full stops and traversal interchangeably.
    #
    # Subkeys will NEVER be duplicated between an alias and a traversal.
    #
    # For example:
    #  {'foo.bar': {'bar': 'ray'}} to look up foo.bar will return {'bar': 'ray'}, not 'ray'
    dict_cursor = lookup_dict
    subkeys = term.split('.')
    subkey = ''

    while len(subkeys) > 0:
        subkey += subkeys.pop(0)

        if subkey in dict_cursor:
            if len(subkeys) == 0:
                break

            dict_cursor = dict_cursor[subkey]
            subkey = ''
        elif len(subkeys) == 0:
            # If there are no keys left to match, return None values
            dict_cursor = None
            subkey = None
        else:
            subkey += '.'

    return dict_cursor, subkey


def set_es_key(lookup_dict, term, value):
    """ Looks up the location that the term maps to and sets it to the given value.
    :returns: True if the value was set successfully, False otherwise.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)

    if value_dict is not None:
        value_dict[value_key] = value
        return True

    return False


def lookup_es_key(lookup_dict, term):
    """ Performs iterative dictionary search for the given term.
    :returns: The value identified by term or None if it cannot be found.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)
    return None if value_key is None else value_dict[value_key]

def hashable(obj):
    """ Convert obj to a hashable obj.
    We use the value of some fields from Elasticsearch as keys for dictionaries. This means
    that whatever Elasticsearch returns must be hashable, and it sometimes returns a list or dict."""
    if not obj.__hash__:
        return str(obj)
    return obj


def format_index(index, start, end):
    """ Takes an index, specified using strftime format, start and end time timestamps,
    and outputs a wildcard based index string to match all possible timestamps. """
    # Convert to UTC
    start -= start.utcoffset()
    end -= end.utcoffset()

    indexes = []
    while start.date() <= end.date():
        indexes.append(start.strftime(index))
        start += datetime.timedelta(days=1)

    return ','.join(indexes)


class EAException(Exception):
    pass

def add_raw_postfix(field):
    if not field.endswith('.raw'):
        field += '.raw'
    return field


def elasticsearch_client(conf):
    """ returns an Elasticsearch instance configured using an es_conn_config """
    es_conn_conf = build_es_conn_config(conf)

    return Elasticsearch(host=es_conn_conf['es_host'],
                         port=es_conn_conf['es_port'],
                         url_prefix=es_conn_conf['es_url_prefix'],
                         use_ssl=es_conn_conf['use_ssl'],
                         verify_certs=es_conn_conf['verify_certs'],
                         connection_class=RequestsHttpConnection,
                         timeout=es_conn_conf['es_conn_timeout'],
                         send_get_body_as=es_conn_conf['send_get_body_as'])


def build_es_conn_config(conf):
    """ Given a conf dictionary w/ raw config properties 'use_ssl', 'es_host', 'es_port'
    'es_username' and 'es_password', this will return a new dictionary
    with properly initialized values for 'es_host', 'es_port', 'use_ssl' and 'http_auth' which
    will be a basicauth username:password formatted string """
    parsed_conf = {}
    parsed_conf['use_ssl'] = False
    parsed_conf['verify_certs'] = True
    parsed_conf['http_auth'] = None
    parsed_conf['es_username'] = None
    parsed_conf['es_password'] = None
    parsed_conf['aws_region'] = None
    parsed_conf['boto_profile'] = None
    parsed_conf['es_host'] = conf['es_host']
    parsed_conf['es_port'] = conf['es_port']
    parsed_conf['es_url_prefix'] = ''
    parsed_conf['es_conn_timeout'] = conf.get('es_conn_timeout', 20)
    parsed_conf['send_get_body_as'] = conf.get('es_send_get_body_as', 'GET')

    if 'es_username' in conf:
        parsed_conf['es_username'] = conf['es_username']
        parsed_conf['es_password'] = conf['es_password']

    if 'aws_region' in conf:
        parsed_conf['aws_region'] = conf['aws_region']

    if 'boto_profile' in conf:
        parsed_conf['boto_profile'] = conf['boto_profile']

    if 'use_ssl' in conf:
        parsed_conf['use_ssl'] = conf['use_ssl']

    if 'verify_certs' in conf:
        parsed_conf['verify_certs'] = conf['verify_certs']

    if 'es_url_prefix' in conf:
        parsed_conf['es_url_prefix'] = conf['es_url_prefix']

    return parsed_conf

def combine_query(must_query, must_not_query):
    pass

def get_query(raw_query, starttime=None, endtime=None, sort=True, timestamp_field='@timestamp', to_ts_func=dt_to_ts, desc=False):
    """ Returns a query dict that will apply a list of filters, filter by
    start and end time, and sort results by timestamp.

    :param raw_query: A lucene query to use.
    :param starttime: A timestamp to use as the start time of the query.
    :param endtime: A timestamp to use as the end time of the query.
    :param sort: If true, sort results by timestamp. (Default True)
    :return: A query dictionary to pass to Elasticsearch.
    """
    simple_query = {
        "query_string": {
            "query": raw_query
        }
    }
    starttime = to_ts_func(starttime)
    endtime = to_ts_func(endtime)
    if starttime and endtime:
        es_filters = {'bool':
                      {'must': [{'range':
                                {timestamp_field: {'gt': starttime,
                                                   'lte': endtime}}}]}}
        query = {'query': {'filtered': {'query': simple_query,
                                        'filter': es_filters}}}
    else:
        query = {'query': simple_query}
    if sort:
        query['sort'] = [
            {timestamp_field: {'order': 'desc' if desc else 'asc'}}]
    return query
