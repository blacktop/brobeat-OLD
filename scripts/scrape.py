#!/usr/bin/env python

from bs4 import BeautifulSoup
import requests
from requests.compat import urljoin
import json
import os
import re
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
consoleHandler = logging.StreamHandler()
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)


def is_url(url):
    regex = re.compile(r'^(?:http|ftp)s?://'  # http:// or https://
                       r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
                       r'localhost|'  # localhost...
                       r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                       r'(?::\d+)?'  # optional port
                       r'(?:/?|[/?]\S+)$',
                       re.IGNORECASE)
    return regex.match(url)


def build_url(current_url, next_url):
    if is_url(next_url):
        return next_url
    else:
        return urljoin(current_url, next_url)


def field_type_lookup(ftype, field):
    type2grok = {
        'time': 'NUMBER',
        'count': 'INT',
        'interval': 'DATA',
        'bool': 'DATA',
        'addr': 'IP',
        'port': 'INT',
        'string': 'DATA',
        'double': 'DATA',
        'geo_location': 'DATA',
        'int': 'INT',
        'transport_proto': 'WORD',
        'conn_id': 'NOTSPACE',
        'set': 'DATA',
        'vector': 'DATA',
    }
    if 'uid' in field:
        return 'NOTSPACE', field
    return type2grok.get(ftype, 'DATA'), field


def doc2grok(fields):
    converted = []
    for field in fields:
        if field['field'] == 'id':
            converted.append('%{IP:orig_h}\\t%{INT:orig_p}\\t%{IP:resp_h}\\t%{INT:resp_p}')
        else:
            converted.append('%%{%s:%s}' % field_type_lookup(field['type'], field['field']))
    return '\\t'.join(converted)


def is_enum(soup, dt_text):
    p = soup.find("dt", id=dt_text).parent.find("p", {"class": "first"})
    if p is not None and 'enum' in p.text:
        return True
    else:
        return False


def parse_p_table(soup, field_name=None, dt_text=None):
    pfields = []
    table = soup.find("dt", id=dt_text).parent.find("table")
    ps = table.find("th", text="Type:").parent.find_all("p")
    for p in ps[1:]:
        nfield_name = p.contents[0].split(':', 1)[0]
        nfield_type = p.contents[1].text
        if field_name is None:
            logger.info(' ===> adding nested field: {}'.format(nfield_name))
            pfields.append(dict(field=nfield_name, type=nfield_type, description=""))
        else:
            logger.info(' ===> adding nested field: {}'.format(field_name + '.' + nfield_name))
            pfields.append(dict(field=field_name + '.' + nfield_name, type=nfield_type, description=""))
    return pfields


def get_nested_fields(field_name, field_type, url):
    nested = []
    skip_list = ["FTP::PendingCmds", "Intel::TypeSet", "Notice::ActionSet"]

    if field_type in skip_list:
        logger.warn(' ===> adding SKIPPED nested field: {}'.format(field_name))
        nested.append(dict(field=field_name, type=field_type, description=""))
    else:
        resp = requests.get(url=url)
        soup = BeautifulSoup(resp.content, "html.parser")
        dt_text = url.split('#')[-1]
        if is_enum(soup, dt_text):
            logger.warn(' ===> adding ENUM field: {}'.format(field_name))
            nested.append(dict(field=field_name, type=field_type, description=""))
        else:
            dl = soup.find("dt", id=dt_text).parent.find("dl", {"class": "docutils"})
            if dl is not None:
                for nfield in list(zip(dl.find_all("dt"), dl.find_all("dd"))):
                    if len(nfield) == 2:
                        nfield_name = nfield[0].contents[0].split(':', 1)[0]
                        nfield_type = nfield[0].contents[1].text
                        if nfield[1].p is not None:
                            nfield_description = nfield[1].p.text.replace('\n', ' ').replace('\r', '').encode('ascii',
                                                                                                              'ignore')
                        else:
                            nfield_description = ""
                        logger.info(' ===> adding nested field: {}'.format(field_name + '.' + nfield_name))
                        nested.append(dict(field=field_name + '.' + nfield_name,
                                           type=nfield_type,
                                           description=nfield_description))
            else:
                logger.warn(' ===> unable to parse nested field type: {}. Trying again...'.format(field_type))
                nested += parse_p_table(soup, field_name, dt_text)
    return nested


def get_log_types():
    url = "https://www.bro.org/sphinx/script-reference/"
    resp = requests.get(url=url + "log-files.html")
    soup = BeautifulSoup(resp.content, "html.parser")
    bro_logs = dict(logs=[])
    for table in soup.find_all("table", {"class": "docutils"}):
        for row in table.find('tbody').find_all('tr'):
            log = {}
            cols = row.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            tds = [ele for ele in cols if ele]
            log['file'] = tds[0]
            log['log_type'] = os.path.splitext(log['file'])[0]
            log['description'] = tds[1]
            log['fields'] = []
            link = row.find('a', href=True)
            # do not add a URL for notice_alarm.log
            if link is not None and 'notice_alarm' not in log['log_type']:
                log['url'] = urljoin(url, link['href'])
                logger.info('adding log type: {}'.format(log['log_type']))
            bro_logs['logs'].append(log)
    return bro_logs


def scrape_bro_docs():
    """ Crawl bro.org docs to extract log types """
    bro_logs = get_log_types()

    for log_type in bro_logs['logs']:
        if log_type.get('url', None):
            resp = requests.get(url=log_type.get('url'), allow_redirects=True)
            soup = BeautifulSoup(resp.content, "html.parser")
            dt_text = log_type.get('url').split('#', 1)[1]
            logger.info('parsing log: {}, field: {}'.format(log_type['file'], dt_text))
            try:
                dl = soup.find("dt", id=dt_text).parent.find("dl", {"class": "docutils"})
                if dl is not None:
                    for dfield in list(zip(dl.find_all("dt"), dl.find_all("dd"))):
                        if len(dfield) == 2:
                            field_name = dfield[0].contents[0].split(':', 1)[0]
                            field_type = dfield[0].contents[1].text
                            if dfield[1].p is not None:
                                field_description = dfield[1].p.text.replace('\n', ' ').replace('\r', '').encode(
                                    'ascii', 'ignore')
                            else:
                                field_description = ""
                            if '::' in field_type:
                                url = build_url(log_type.get('url'), dfield[0].a['href'])
                                log_type['fields'] += get_nested_fields(field_name, field_type, url)
                            else:
                                log_type['fields'].append(dict(field=field_name,
                                                               type=field_type,
                                                               description=field_description))
                else:
                    logger.warn(' ===> unable to parse fields for log: {}. Trying again...'.format(log_type['file']))
                    log_type['fields'] += parse_p_table(soup, field_name=None, dt_text=dt_text)
            except Exception as e:
                logger.error('parsing log: {}, field: {}'.format(log_type['file'], dt_text))
                logger.exception(e.message)
            log_type['pattern'] = get_log_grok_pattern(log_type)
    with open('bro-logs.json', 'w') as jsonfile:
        json.dump(bro_logs, jsonfile)
    return bro_logs


def get_log_grok_pattern(logtype):
    return dict(name='BRO_' + logtype['log_type'].upper(), pattern=doc2grok(logtype.get('fields')))


def convert_docs_to_grok_patterns(bro_logs):
    """ Build pattern file """
    with open('../logstash/patterns/generated-bro', 'w') as patternfile:
        patternfile.write('# BRO-DOC-GENERATED patterns\n')
        patternfile.write('# author: blacktop\n')
        patternfile.write('# https://www.bro.org/sphinx/script-reference/log-files.html')
        patternfile.write('\n\n')
        for logtype in bro_logs['logs']:
            patternfile.write('# ' + logtype.get('file') + '\n')
            if logtype.get('fields'):
                patternfile.write(logtype['pattern'].get('name') + ' ' + logtype['pattern'].get('pattern'))
            patternfile.write('\n\n')


if __name__ == '__main__':
    convert_docs_to_grok_patterns(scrape_bro_docs())
