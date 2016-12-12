# -*- coding: utf-8 -*-
import datetime
import json
import logging
import os
import signal
import sys
import traceback
from socket import error

import argparse
import yaml
from config import load_config
from elasticsearch.exceptions import ElasticsearchException

from es_util import ElastReporter_logger
from es_util import elasticsearch_client
from es_util import get_query

from time_util import dt_to_ts
from time_util import dt_to_unixms
from time_util import td_add
from time_util import ts_now


class ElastReporter():
    """ The main ElastReporter runner. This class holds all state about active rules,
    controls when queries are run, and passes information between rules and alerts.

    :param args: An argparse arguments instance. Should contain debug and start

    :param conf: The configuration dictionary. At the top level, this
    contains global options, and under 'rules', contains all state relating
    to rules and alerts. In each rule in conf['rules'], the RuleType and Alerter
    instances live under 'type' and 'alerts', respectively. The conf dictionary
    should not be passed directly from a configuration file, but must be populated
    by config.py:load_config instead. """

    def parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', action='store', dest='config',
                            default="config.yaml", help='Global config file (default: config.yaml)')
        parser.add_argument('--debug', action='store_true', dest='debug',
                            help='Suppresses alerts and prints information instead')
        parser.add_argument('--start', dest='start', help='YYYY-MM-DDTHH:MM:SS Start querying from this timestamp.'
                                                          'Use "NOW" to start from current time. (Default: present)')
        parser.add_argument(
            '--end', dest='end', help='YYYY-MM-DDTHH:MM:SS Query to this timestamp. (Default: present)')
        parser.add_argument('--verbose', action='store_true', dest='verbose',
                            help='Increase verbosity without suppressing alerts')
        parser.add_argument('--es_debug', action='store_true', dest='es_debug',
                            help='Enable verbose logging from Elasticsearch queries')
        parser.add_argument('--es_debug_trace', action='store', dest='es_debug_trace',
                            help='Enable logging from Elasticsearch queries as curl command. Queries will be logged to file')
        self.args = parser.parse_args(args)

    def __init__(self, args):
        self.parse_args(args)
        self.debug = self.args.debug
        self.verbose = self.args.verbose

        if self.verbose or self.debug:
            ElastReporter_logger.setLevel(logging.DEBUG)

        if self.debug:
            ElastReporter_logger.info(
                "Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them, use --verbose.")

        if not self.args.es_debug:
            logging.getLogger('elasticsearch').setLevel(logging.WARNING)

        if self.args.es_debug_trace:
            tracer = logging.getLogger('elasticsearch.trace')
            tracer.setLevel(logging.INFO)
            tracer.addHandler(logging.FileHandler(self.args.es_debug_trace))

        self.conf = load_config(self.args)
        self.max_query_size = self.conf['max_query_size']
        self.scroll_keepalive = self.conf['scroll_keepalive']
        self.writeback_index = self.conf['writeback']['index']
        self.num_hits = 0
        self.current_es = elasticsearch_client(self.conf)
        self.current_es_addr = None
        self.silence_cache = {}
        self.days_range = self.conf['days_range']

        self.writeback_es = elasticsearch_client(self.conf['writeback'])

    @staticmethod
    def get_index(rule, starttime=None, endtime=None):
        """ Gets the index for a rule. If strftime is set and starttime and endtime
        are provided, it will return a comma seperated list of indices. If strftime
        is set but starttime and endtime are not provided, it will replace all format
        tokens with a wildcard. """
        index = rule['index']
        if rule.get('use_strftime_index'):
            if starttime and endtime:
                return format_index(index, starttime, endtime)
            else:
                # Replace the substring containing format characters with a *
                format_start = index.find('%')
                format_end = index.rfind('%') + 2
                return index[:format_start] + '*' + index[format_end:]
        else:
            return index

    def get_pipeline_queries(self):
        """Query for pipeline definitions and return the array of queries"""
        ElastReporter_logger.debug("conf is {}".format(self.conf))
        #self.current_es = elasticsearch_client(self.conf)

        pl_query = get_query("*")
        ElastReporter_logger.debug(
            "Query to collect pipelines {}".format(pl_query))
        scroll_keepalive = '30s'
        index = self.writeback_index
        res = self.writeback_es.search(scroll=scroll_keepalive, index=index,
                                       body=pl_query, ignore_unavailable=True,
                                       size=1000)
        #ElastReporter_logger.debug("result is {}".format(str(res)))
        #ElastReporter_logger.debug("hits: {}".format(res))
        hits = res['hits']['hits']
        named_queries = []
        for hit in hits:
            query = hit['_source']['pipeline_metadata']['query']
            id = hit['_id']
            named_queries.append({'_id': id, 'query': query})
        ElastReporter_logger.debug("Queries are {}".format(named_queries))
        return named_queries

    def not_in_pipelines(self, named_queries, index):
        """Return None if everything's in pipelines, sample of item out of pipeline if there is anything."""
        raw_query = ""
        for iter_q in named_queries:
            raw_query += " OR (" + iter_q['query'] + ")"
        raw_query = "NOT (" + raw_query[4:] + ")"
        ElastReporter_logger.error('RAW query is:{}'.format(raw_query))
        endtime = ts_now()
        starttime = endtime + datetime.timedelta(days=-self.days_range)
        peer_query = get_query(raw_query, starttime=starttime,
                               endtime=endtime, to_ts_func=dt_to_unixms)
        scroll_keepalive = '30s'
        res = self.current_es.search(scroll=scroll_keepalive, index=index,
                                     body=peer_query, ignore_unavailable=True)
        if res['hits']['total'] != 0:
            ElastReporter_logger.error('Detected items out of pipelines:')
            ElastReporter_logger.info('{0}'.format(json.dumps(res['hits']['hits'], indent=2)))
            return res['hits']['hits']
        else:
            return None

    def validate_consistency(self, named_queries, index):
        for i, query in enumerate(named_queries):
            peer_queries = named_queries[:]
            del peer_queries[i]
            conflict = self.validate_against_peers(query, peer_queries, index)
            if conflict:
                cnfl = self.pinpoint_conflict(query, peer_queries, index)
                if not cnfl:
                    import pdb; pdb.set_trace()
                ElastReporter_logger.error(
                    'Pipeline {0} conflicts with pipeline {1}'.format(
                        query['_id'], cnfl['_id']))
                precise_conflict = self.validate_against_peers(query, [cnfl], index)
                ElastReporter_logger.info(
                    'Conflict detected, sample: {0}'.format(
                        json.dumps(precise_conflict, indent=2)))
            else:
                ElastReporter_logger.info(
                    'Pipeline {0} doesn\'t have conflicts'.format(query['_id']))

    def validate_against_peers(self, query, named_queries, index):
        """Checks if there is a conflict between query and named_queries

        Returns: None if there is no conflict or sample conflict result"""
        ElastReporter_logger.debug(
            "Validating pipeline '{0}' against peers".format(query['_id']))
        # ElastReporter_logger.debug('Peers: {0}'.format(named_queries))
        peer_lc_query = ""
        for iter_q in named_queries:
            peer_lc_query += " OR (" + iter_q['query'] + ")"
        peer_lc_query = "(" + peer_lc_query[4:] + ")"
        peer_lc_query += "AND (" + query['query'] + ")"
        endtime = ts_now()
        starttime = endtime + datetime.timedelta(days=-self.days_range)
        peer_query = get_query(peer_lc_query, starttime=starttime,
                               endtime=endtime, to_ts_func=dt_to_unixms)
        scroll_keepalive = '30s'
        res = self.current_es.search(scroll=scroll_keepalive, index=index,
                                     body=peer_query, ignore_unavailable=True)
        # ElastReporter_logger.debug("result is {}".format(str(res)))
        if res['hits']['total'] != 0:
            #            self.pinpoint_conflict(query, named_queries, index)
            return res['hits']['hits'][0]
        else:
            return None

    def pinpoint_conflict(self, query, named_queries, index):
        """Return id of the first conflicting pipeline.

        query is not in named_queries, initial conflict is present."""
        if len(named_queries) == 0:
            return None
        if len(named_queries) == 1:
            res = self.validate_against_peers(query, named_queries, index)
            if res:
                return named_queries[0]
        left_peers = named_queries[:len(named_queries) / 2]
        left_res = self.validate_against_peers(query, left_peers, index)
        if left_res:
            return self.pinpoint_conflict(query, left_peers, index)
        else:
            right_peers = named_queries[len(named_queries) / 2:]
            right_res = self.validate_against_peers(query, right_peers, index)
            if right_res:
                return self.pinpoint_conflict(query, right_peers, index)

    def writeback(self, doc_type, body):
        # Convert any datetime objects to timestamps
        for key in body.keys():
            if isinstance(body[key], datetime.datetime):
                body[key] = dt_to_ts(body[key])
        if self.debug:
            ElastReporter_logger.info("Skipping writing to ES: %s" % (body))
            return None

        if '@timestamp' not in body:
            body['@timestamp'] = dt_to_ts(ts_now())
        if self.writeback_es:
            try:
                res = self.writeback_es.create(index=self.writeback_index,
                                               doc_type=doc_type, body=body)
                return res
            except ElasticsearchException as e:
                logging.exception(
                    "Error writing alert info to Elasticsearch: %s" % (e))
                self.writeback_es = None

    def handle_error(self, message, data=None):
        ''' Logs message at error level and writes message, data and traceback to Elasticsearch. '''
        if not self.writeback_es:
            self.writeback_es = elasticsearch_client(self.conf)

        logging.error(message)
        body = {'message': message}
        tb = traceback.format_exc()
        body['traceback'] = tb.strip().split('\n')
        if data:
            body['data'] = data
        self.writeback('ElastReporter_error', body)

    def handle_uncaught_exception(self, exception, rule):
        """ Disables a rule and sends a notification. """
        logging.error(traceback.format_exc())
        self.handle_error('Uncaught exception running rule %s: %s' % (
            rule['name'], exception), {'rule': rule['name']})
        if self.disable_rules_on_error:
            self.rules = [running_rule for running_rule in self.rules if running_rule[
                'name'] != rule['name']]
            self.disabled_rules.append(rule)
            ElastReporter_logger.info('Rule %s disabled', rule['name'])
        if self.notify_email:
            self.send_notification_email(exception=exception, rule=rule)


def handle_signal(signal, frame):
    ElastReporter_logger.info(
        'SIGINT received, stopping ES Reporter...')
    # use os._exit to exit immediately and avoid someone catching SystemExit
    os._exit(0)


def main(args=None):
    signal.signal(signal.SIGINT, handle_signal)
    if not args:
        args = sys.argv[1:]
    client = ElastReporter(args)
    named_queries = client.get_pipeline_queries()
    client.validate_consistency(named_queries, 'logstash-*')
    client.not_in_pipelines(named_queries, 'logstash-*')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
