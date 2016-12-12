# -*- coding: utf-8 -*-
import datetime
import logging

import dateutil.parser
import dateutil.tz

logging.basicConfig()

def ts_to_dt(timestamp):
    if isinstance(timestamp, datetime.datetime):
        logging.warning('Expected str timestamp, got datetime')
        return timestamp
    dt = dateutil.parser.parse(timestamp)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_ts(dt):
    if not isinstance(dt, datetime.datetime):
        logging.warning('Expected datetime, got %s' % (type(dt)))
        return dt
    ts = dt.isoformat()
    # Round microseconds to milliseconds
    if dt.tzinfo is None:
        # Implicitly convert local times to UTC
        return ts + 'Z'
    # isoformat() uses microsecond accuracy and timezone offsets
    # but we should try to use millisecond accuracy and Z to indicate UTC
    return ts.replace('000+00:00', 'Z').replace('+00:00', 'Z')

def ts_now():
    return datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())


def inc_ts(timestamp, milliseconds=1):
    """Increment a timestamp by milliseconds."""
    dt = ts_to_dt(timestamp)
    dt += datetime.timedelta(milliseconds=milliseconds)
    return dt_to_ts(dt)

def ts_add(ts, td):
    """ Allows a timedelta (td) add operation on a string timestamp (ts) """
    return dt_to_ts(ts_to_dt(ts) + td)

def td_add(ts, td):
    """ Allows a timedelta (td) add operation on a string timestamp (ts) """
    return ts_to_dt(ts) + td


def seconds(td):
    return td.seconds + td.days * 24 * 3600


def total_seconds(td):
    # For python 2.6 compatability
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def dt_to_int(dt):
    dt = dt.replace(tzinfo=None)
    return int(total_seconds((dt - datetime.datetime.utcfromtimestamp(0))) * 1000)


def unixms_to_dt(ts):
    return unix_to_dt(float(ts) / 1000)


def unix_to_dt(ts):
    dt = datetime.datetime.utcfromtimestamp(float(ts))
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_unix(dt):
    #import pdb; pdb.set_trace()
    return total_seconds(dt - datetime.datetime(1970, 1, 1, tzinfo=dateutil.tz.tzutc()))


def dt_to_unixms(dt):
    return dt_to_unix(dt) * 1000
