#!/usr/bin/python

# Usage: ./updateFallbackDirs.py > src/or/fallback_dirs.inc
# Then read the generated code to ensure no-one slipped anything funny in it

# Script by weasel, April 2015
# Portions by gsathya & karsten, 2013
# Modifications by teor, May 2015

import StringIO
import string
import re
import datetime
import gzip
import os.path
import json
import math
import sys
import urllib
import urllib2
import hashlib
# bson_lazy provides bson
#from bson import json_util

import logging
logging.basicConfig(level=logging.INFO)

ONIONOO = 'https://onionoo.torproject.org/'

ADDRESS_AND_PORT_STABLE_DAYS = 120
# What time-weighted-fraction of these flags must FallbackDirs:
# Equal or Exceed?
CUTOFF_RUNNING = .95
CUTOFF_V2DIR = .95
CUTOFF_GUARD = .95
# Equal or Fall Under?
# .00 means no bad exits
PERMITTED_BADEXIT = .00

AGE_ALPHA = 0.99 # older entries' weights are adjusted with ALPHA^(age in days)

ONIONOO_SCALE_ONE = 999.

def parse_ts(t):
  return datetime.datetime.strptime(t, "%Y-%m-%d %H:%M:%S")

def onionoo_fetch(what, **kwargs):
  params = kwargs
  params['type'] = 'relay'
  #params['limit'] = 10
  params['first_seen_days'] = '%d-'%(ADDRESS_AND_PORT_STABLE_DAYS,)
  params['last_seen_days'] = '-7'
  params['flag'] = 'V2Dir'
  url = ONIONOO + what + '?' + urllib.urlencode(params)

  #quoted_url = urllib.quote_plus(url)
  # Unfortunately, the URL is too long for some OS filenames,
  # but we still don't want to get files from different URLs mixed up
  base_file_name = what + '-' + hashlib.sha1(url).hexdigest()

  FULL_URL_SUFFIX = '.full_url'
  full_url_file_name = base_file_name + FULL_URL_SUFFIX
  MAX_FULL_URL_LENGTH = 1024

  LAST_MODIFIED_SUFFIX = '.last_modified'
  last_modified_file_name = base_file_name + LAST_MODIFIED_SUFFIX
  MAX_LAST_MODIFIED_LENGTH = 64

  JSON_SUFFIX = '.json'
  json_file_name = base_file_name + JSON_SUFFIX

  # optionally, store the full URL to a file for debugging
  # no need to compare as long as you trust SHA-1
  try:
    with open(full_url_file_name, 'w') as f:
      f.write(url[0:MAX_FULL_URL_LENGTH])
  except EnvironmentError, error:
    logging.debug('Writing full URL file %s failed: %d: %s'%
                  (full_url_file_name,
                   error.errno,
                   error.strerror)
                  )

  request = urllib2.Request(url)
  request.add_header('Accept-encoding', 'gzip')

  # optionally, load the last modified date from the file, if it exists
  try:
    if os.path.isfile(last_modified_file_name):
      with open(last_modified_file_name, 'r') as f:
        last_mod_date = f.read(MAX_LAST_MODIFIED_LENGTH)
        request.add_header('If-modified-since', last_mod_date)
  except EnvironmentError, error:
    logging.debug('Loading last modified file %s failed: %d: %s'%
                  (last_modified_file_name,
                   error.errno,
                   error.strerror)
                  )

  response_code = 0
  try:
    response = urllib2.urlopen(request)
    response_code = response.getcode()
  except urllib2.HTTPError, error:
    response_code = error.code
    if response_code == 304: # Not Modified
      pass
    else:
      raise Exception("Could not get "+url+": "+ str(error.code) + ": " + error.reason)

  if response_code == 200: # OK

    if response.info().get('Content-Encoding') == 'gzip':
      buf = StringIO.StringIO( response.read() )
      f = gzip.GzipFile(fileobj=buf)
      response_json = json.load(f)
    else:
      response_json = json.load(response)

    with open(json_file_name, 'w') as f:
      # use the most compact json representation to save space
      json.dump(response_json, f, separators=(',',':'))

    # optionally, store the last modified date in its own file
    try:
      if response.info().get('Last-modified') is not None:
        with open(last_modified_file_name, 'w') as f:
          f.write(response.info().get('Last-Modified')[0:MAX_LAST_MODIFIED_LENGTH])
    except EnvironmentError, error:
      logging.debug('Writing last modified file %s failed: %d: %s'%
                    (last_modified_file_name,
                     error.errno,
                     error.strerror)
                    )

  elif response_code == 304: # Not Modified

    # An exception here can probably be resolved by deleting the .last_modified
    # and .json files, and re-running the script
    try:
      with open(json_file_name, 'r') as f:
        response_json = json.load(f)
    except EnvironmentError, error:
      raise Exception('Reading not-modified json file %s failed: %d: %s'%
                    (json_file_name,
                     error.errno,
                     error.strerror)
                    )

  else: # Unexpected HTTP response code not covered in the HTTPError above
    raise Exception("Unexpected HTTP response code to "+url+": "+ str(response_code))

  return response_json

def dummy_fetch(what, **kwargs):
  with open('x-'+what) as f:
    return json.load(f)

def fetch(what, **kwargs):
  #x = onionoo_fetch(what, **kwargs)
  # don't use sort_keys, as the order of or_addresses is significant
  #print json.dumps(x, indent=4, separators=(',', ': '))
  #sys.exit(0)

  return onionoo_fetch(what, **kwargs)
  #return dummy_fetch(what, **kwargs)



class Candidate(object):
  CUTOFF_ADDRESS_AND_PORT_STABLE = datetime.datetime.now() - datetime.timedelta(ADDRESS_AND_PORT_STABLE_DAYS)

  def __init__(self, details):
    for f in ['fingerprint', 'nickname', 'last_changed_address_or_port', 'consensus_weight', 'or_addresses', 'dir_address']:
      if not f in details: raise Exception("Document has no %s field."%(f,))

    if not 'contact' in details: details['contact'] = None
    details['last_changed_address_or_port'] = parse_ts(details['last_changed_address_or_port'])

    self._data = details
    self._stable_sort_or_addresses()

    self._fpr = self._data['fingerprint']
    self._running = self._guard = self._v2dir = 0.
    self._compute_orport()
    if self.orport is None:
      raise Exception("Failed to get an orport for %s."%(self._fpr,))
    self._compute_ipv6addr()
    if self.ipv6addr is None:
      logging.debug("Failed to get an ipv6 address for %s."%(self._fpr,))

  def _stable_sort_or_addresses(self):
    # replace self._data['or_addresses'] with a stable ordering,
    # sorting the secondary addresses in string order
    # leave the received order in self._data['or_addresses_raw']
    self._data['or_addresses_raw'] = self._data['or_addresses']
    or_address_primary = self._data['or_addresses'][:1]
    # subsequent entries in the or_addresses array are in an arbitrary order
    # so we stabilise the addresses by sorting them in string order
    or_addresses_secondaries_stable = sorted(self._data['or_addresses'][1:])
    or_addresses_stable = or_address_primary + or_addresses_secondaries_stable
    self._data['or_addresses'] = or_addresses_stable

  def get_fingerprint(self):
    return self._fpr

  # is_valid_ipv[46]_address by gsathya, karsten, 2013
  # https://trac.torproject.org/projects/tor/attachment/ticket/8374/dir_list.2.py

  @staticmethod
  def is_valid_ipv4_address(address):
    if not isinstance(address, (str, unicode)):
      return False

    # check if there are four period separated values
    if address.count(".") != 3:
      return False

    # checks that each value in the octet are decimal values between 0-255
    for entry in address.split("."):
      if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
        return False
      elif entry[0] == "0" and len(entry) > 1:
        return False  # leading zeros, for instance in "1.2.3.001"

    return True

  @staticmethod
  def is_valid_ipv6_address(address):
    if not isinstance(address, (str, unicode)):
      return False

    # remove brackets
    address = address[1:-1]

    # addresses are made up of eight colon separated groups of four hex digits
    # with leading zeros being optional
    # https://en.wikipedia.org/wiki/IPv6#Address_format

    colon_count = address.count(":")

    if colon_count > 7:
      return False  # too many groups
    elif colon_count != 7 and not "::" in address:
      return False  # not enough groups and none are collapsed
    elif address.count("::") > 1 or ":::" in address:
      return False  # multiple groupings of zeros can't be collapsed

    found_ipv4_on_previous_entry = False
    for entry in address.split(":"):
      # If an IPv6 address has an embedded IPv4 address,
      # it must be the last entry
      if found_ipv4_on_previous_entry:
        return False
      if not re.match("^[0-9a-fA-f]{0,4}$", entry):
        if not Candidate.is_valid_ipv4_address(entry):
          return False
        else:
          found_ipv4_on_previous_entry = True

    return True

  def _compute_orport(self):
    # Choose the first ORPort that's on the same IPv4 address as the DirPort.
    # In rare circumstances, this might not be the primary ORPort address.
    # However, _stable_sort_or_addresses() ensures we choose the same one
    # every time, even if onionoo changes the order of the secondaries.
    (diripaddr, dirport) = self._data['dir_address'].split(':', 2)
    self.orport = None
    for i in self._data['or_addresses']:
      if i != self._data['or_addresses'][0]:
        logging.debug('Secondary IPv4 Address Used for %s: %s'%(self._fpr, i))
      (ipaddr, port) = i.rsplit(':', 1)
      if (ipaddr == diripaddr) and Candidate.is_valid_ipv4_address(ipaddr):
        self.orport = int(port)
        return

  def _compute_ipv6addr(self):
    # Choose the first IPv6 address that uses the same port as the ORPort
    # Or, choose the first IPv6 address in the list
    # _stable_sort_or_addresses() ensures we choose the same IPv6 address
    # every time, even if onionoo changes the order of the secondaries.
    self.ipv6addr = None
    # Choose the first IPv6 address that uses the same port as the ORPort
    for i in self._data['or_addresses']:
      (ipaddr, port) = i.rsplit(':', 1)
      if (port == self.orport) and Candidate.is_valid_ipv6_address(ipaddr):
        self.ipv6addr = ipaddr
        return
    # Choose the first IPv6 address in the list
    for i in self._data['or_addresses']:
      (ipaddr, port) = i.rsplit(':', 1)
      if Candidate.is_valid_ipv6_address(ipaddr):
        self.ipv6addr = ipaddr
        return

  @staticmethod
  def _extract_generic_history(history, which='unknown'):
    # given a tree like this:
    #   {
    #     "1_month": {
    #         "count": 187,
    #         "factor": 0.001001001001001001,
    #         "first": "2015-02-27 06:00:00",
    #         "interval": 14400,
    #         "last": "2015-03-30 06:00:00",
    #         "values": [
    #             999,
    #             999
    #         ]
    #     },
    #     "1_week": {
    #         "count": 169,
    #         "factor": 0.001001001001001001,
    #         "first": "2015-03-23 07:30:00",
    #         "interval": 3600,
    #         "last": "2015-03-30 07:30:00",
    #         "values": [ ...]
    #     },
    #     "1_year": {
    #         "count": 177,
    #         "factor": 0.001001001001001001,
    #         "first": "2014-04-11 00:00:00",
    #         "interval": 172800,
    #         "last": "2015-03-29 00:00:00",
    #         "values": [ ...]
    #     },
    #     "3_months": {
    #         "count": 185,
    #         "factor": 0.001001001001001001,
    #         "first": "2014-12-28 06:00:00",
    #         "interval": 43200,
    #         "last": "2015-03-30 06:00:00",
    #         "values": [ ...]
    #     }
    #   },
    # extract exactly one piece of data per time interval, using smaller intervals where available.
    #
    # returns list of (age, length, value) dictionaries.

    generic_history = []

    periods = history.keys()
    periods.sort(key = lambda x: history[x]['interval'])
    now = datetime.datetime.now()
    newest = now
    for p in periods:
      h = history[p]
      interval = datetime.timedelta(seconds = h['interval'])
      this_ts = parse_ts(h['last'])

      if (len(h['values']) != h['count']):
        logging.warn('Inconsistent value count in %s document for %s'%(p, which,))
      for v in reversed(h['values']):
        if (this_ts <= newest):
          generic_history.append(
            { 'age': (now - this_ts).total_seconds(),
              'length': interval.total_seconds(),
              'value': v
            })
          newest = this_ts
        this_ts -= interval

      if (this_ts + interval != parse_ts(h['first'])):
        logging.warn('Inconsistent time information in %s document for %s'%(p, which,))

    #print json.dumps(generic_history, sort_keys=True, indent=4, separators=(',', ': '))
    return generic_history

  @staticmethod
  def _avg_generic_history(generic_history):
    a = []
    for i in generic_history:
      w = i['length'] * math.pow(AGE_ALPHA, i['age']/(3600*24))
      a.append( (i['value'] * w, w) )

    sv = math.fsum(map(lambda x: x[0], a))
    sw = math.fsum(map(lambda x: x[1], a))

    return sv/sw

  def _add_generic_history(self, history):
    periods = r['read_history'].keys()
    periods.sort(key = lambda x: r['read_history'][x]['interval'] )

    print periods

  def add_running_history(self, history):
    pass

  def add_uptime(self, uptime):
    logging.debug('Adding uptime %s.'%(self._fpr,))

    # flags we care about: Running, V2Dir, Guard
    if not 'flags' in uptime:
      logging.debug('No flags in document for %s.'%(self._fpr,))
      return

    for f in ['Running', 'Guard', 'V2Dir']:
      if not f in uptime['flags']:
        logging.debug('No %s in flags for %s.'%(f, self._fpr,))
        return

    running = self._extract_generic_history(uptime['flags']['Running'], '%s-Running'%(self._fpr,))
    guard = self._extract_generic_history(uptime['flags']['Guard'], '%s-Guard'%(self._fpr,))
    v2dir = self._extract_generic_history(uptime['flags']['V2Dir'], '%s-V2Dir'%(self._fpr,))
    if 'BadExit' in uptime['flags']:
      badexit = self._extract_generic_history(uptime['flags']['BadExit'], '%s-BadExit'%(self._fpr,))

    self._running = self._avg_generic_history(running) / ONIONOO_SCALE_ONE
    self._guard = self._avg_generic_history(guard) / ONIONOO_SCALE_ONE
    self._v2dir = self._avg_generic_history(v2dir) / ONIONOO_SCALE_ONE
    self._badexit = None
    if 'BadExit' in uptime['flags']:
      self._badexit = self._avg_generic_history(badexit) / ONIONOO_SCALE_ONE

  def is_candidate(self):
    if self._data['last_changed_address_or_port'] > self.CUTOFF_ADDRESS_AND_PORT_STABLE:
      logging.debug('%s not a candidate: changed address/port recently (%s)',
        self._fpr, self._data['last_changed_address_or_port'])
      return False
    if self._running < CUTOFF_RUNNING:
      logging.debug('%s not a candidate: running avg too low (%lf)', self._fpr, self._running)
      return False
    if self._guard < CUTOFF_GUARD:
      logging.debug('%s not a candidate: guard avg too low (%lf)', self._fpr, self._guard)
      return False
    if self._v2dir < CUTOFF_V2DIR:
      logging.debug('%s not a candidate: v2dir avg too low (%lf)', self._fpr, self._v2dir)
      return False
    if self._badexit is not None and self._badexit > PERMITTED_BADEXIT:
      logging.debug('%s not a candidate: badexit avg too high (%lf)', self._fpr, self._badexit)
      return False
    # if the relay doesn't report a version, also exclude the relay
    if not self._data.has_key('recommended_version') or not self._data['recommended_version']:
      return False
    return True

  @staticmethod
  def _remove_bad_chars(raw_string, bad_char_list):
    # Remove each character in the bad_char_list
    escaped_string = raw_string
    for c in bad_char_list:
      escaped_string = escaped_string.replace(c, '')
    return escaped_string

  @staticmethod
  def _cleanse_whitespace(raw_string):
    # Replace all whitespace characters with a space
    escaped_string = raw_string
    for c in string.whitespace:
      escaped_string = escaped_string.replace(c, ' ')
    return escaped_string

  @staticmethod
  def _cleanse_c_multiline_comment(raw_string):
    # Prevent a malicious Nickname/ContactInfo string from breaking out
    # of a C-style multiline comment
    # This also removes '/*' and '//'
    bad_char_list = '*/'
    # Prevent a malicious string from using C nulls
    bad_char_list += '\0'
    # Prevent attacks like '**//' -> '*/' by removing bad characters entirely
    escaped_string = Candidate._remove_bad_chars(raw_string, bad_char_list)
    # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
    escaped_string = Candidate._cleanse_whitespace(escaped_string)
    # Put the string on a single line, all by itself
    escaped_string += '\n'
    # Some compilers may further process the content of comments
    # There isn't much we can do to cover every possible case
    # But comment-based directives are typically only advisory
    return escaped_string

  @staticmethod
  def _cleanse_c_string(raw_string):
    # Prevent a malicious address/fingerprint string from breaking out
    # of a C-style string
    bad_char_list = '"'
    # Prevent a malicious string from using escapes
    bad_char_list += '\\'
    # Prevent a malicious string from using C nulls
    bad_char_list += '\0'
    # Be safer by removing bad characters entirely
    escaped_string = Candidate._remove_bad_chars(raw_string, bad_char_list)
    # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
    escaped_string = Candidate._cleanse_whitespace(escaped_string)
    # Some compilers may further process the content of strings
    # There isn't much we can do to cover every possible case
    # But this typically only results in changes to the string data
    return escaped_string

  def fallbackdir_line(self):
    # /*
    # nickname
    # [contact]
    # */
    # "address:port orport=port id=fingerprint [weight=num]",
    # Multiline C comment
    s = '/*\n'
    s += Candidate._cleanse_c_multiline_comment(self._data['nickname'])
    if self._data['contact'] is not None:
      s += Candidate._cleanse_c_multiline_comment(self._data['contact'])
    s += '*/'
    s += '\n'
    # Single-Line C string with trailing comma (part of a string list)
    s += '"%s orport=%d id=%s weight=%d'%(
            Candidate._cleanse_c_string(self._data['dir_address']),
            self.orport,                   # Integers don't need escaping
            Candidate._cleanse_c_string(self._fpr),
            self._data['consensus_weight'] # Integers don't need escaping
          )
    if self.ipv6addr is not None:
      s += ' ipv6=%s'%(Candidate._cleanse_c_string(self.ipv6addr))
    s += '",'
    return s

class CandidateList(dict):
  def __init__(self):
    pass

  def _add_relay(self, details):
    if not 'dir_address' in details: return
    c = Candidate(details)
    self[ c.get_fingerprint() ] = c

  def _add_uptime(self, uptime):
    try:
      fpr = uptime['fingerprint']
    except KeyError:
      raise Exception("Document has no fingerprint field.")

    try:
      c = self[fpr]
    except KeyError:
      logging.debug('Got unknown relay %s in uptime document.'%(fpr,))
      return

    c.add_uptime(uptime)

  def _add_details(self):
    logging.debug('Loading details document.')
    d = fetch('details', fields='fingerprint,nickname,contact,last_changed_address_or_port,consensus_weight,or_addresses,dir_address,recommended_version')
    logging.debug('Loading details document done.')

    if not 'relays' in d: raise Exception("No relays found in document.")
    for r in d['relays']: self._add_relay(r)

  def _add_uptimes(self):
    logging.debug('Loading uptime document.')
    d = fetch('uptime')
    logging.debug('Loading uptime document done.')

    if not 'relays' in d: raise Exception("No relays found in document.")
    for r in d['relays']: self._add_uptime(r)

  def add_relays(self):
    self._add_details()
    self._add_uptimes()


  def compute_fallbacks(self):
    self.fallbacks = map(lambda x: self[x], sorted(filter(lambda x: self[x].is_candidate(), self.keys())))

def list_fallbacks():
  """ Fetches required onionoo documents and evaluates the
      t-shirt qualification criteria for each of the relays """

  candidates = CandidateList()
  candidates.add_relays()
  candidates.compute_fallbacks()

  for x in candidates.fallbacks:
    print x.fallbackdir_line()
    #print json.dumps(candidates[x]._data, sort_keys=True, indent=4, separators=(',', ': '), default=json_util.default)

if __name__ == "__main__":
  list_fallbacks()
