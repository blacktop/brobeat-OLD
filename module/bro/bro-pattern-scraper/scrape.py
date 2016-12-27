from bs4 import BeautifulSoup
import requests
import json
import os


def field_type_lookup(ftype, field):
    type2grok = {
        'time': 'NUMBER',
        'count': 'INT',
        'interval': 'NUMBER',
        'bool': 'GREEDYDATA',
        'addr': 'IP',
        'port': 'INT',
        'string': 'GREEDYDATA',
        'double': 'GREEDYDATA',
        'geo_location': 'GREEDYDATA',
        'int': 'INT',
        'transport_proto': 'WORD',
        'conn_id': 'NOTSPACE',
        'set': 'GREEDYDATA',
        'vector': 'GREEDYDATA',
    }
    if 'uid' in field:
        return 'NOTSPACE', field
    return type2grok.get(ftype, 'GREEDYDATA'), field


def doc2grok(fields):
    converted = []
    for field in fields:
        if field['field'] == 'id':
            converted.append('%{IP:orig_h}\\t%{INT:orig_p}\\t%{IP:resp_h}\\t%{INT:resp_p}')
        else:
            converted.append('%%{%s:%s}' % field_type_lookup(field['type'], field['field']))
    return '\\t'.join(converted)


def scrape_bro_docs():
    """ Crawl Bro NSM docs to extract log types """
    url = "https://www.bro.org/sphinx/script-reference/"
    resp = requests.get(url=url + "log-files.html")
    soup = BeautifulSoup(resp.content, "html.parser")

    bro_logs = dict(logs=[])
    for table in soup.find_all("table", {"class": "docutils"}):
        for row in table.find('tbody').find_all('tr'):
            log = {}
            link = row.find('a', href=True)
            if link:
                log['url'] = url + link['href']
            cols = row.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            tds = [ele for ele in cols if ele]
            log['file'] = tds[0]
            log['log_type'] = os.path.splitext(log['file'])[0]
            log['description'] = tds[1]
            log['fields'] = []
            bro_logs['logs'].append(log)
    for log_type in bro_logs['logs']:
        if log_type.get('url', None):
            resp = requests.get(url=log_type.get('url'))
            soup = BeautifulSoup(resp.content, "html.parser")
            for dt in soup.find_all("dt"):
                if '&log' in dt.text:
                    log_type['fields'].append(dict(field=dt.contents[0].split(':', 1)[0], type=dt.contents[1].text))
    with open('bro-logs.json', 'w') as jsonfile:
        json.dump(bro_logs, jsonfile)
    return bro_logs


def convert_docs_to_grok_patterns(bro_logs):
    """ Build pattern file """
    with open('../patterns/generated-bro', 'w') as patternfile:
        patternfile.write('# BRO-DOC-GENERATED patterns\n')
        patternfile.write('# author: blacktop\n')
        patternfile.write('# https://www.bro.org/sphinx/script-reference/log-files.html')
        patternfile.write('\n\n')
        for logtype in bro_logs['logs']:
            patternfile.write('# ' + logtype.get('file') + '\n')
            if logtype.get('fields'):
                patternfile.write('BRO_' + logtype['log_type'].upper() + ' ' + doc2grok(logtype.get('fields')))
            patternfile.write('\n\n')


convert_docs_to_grok_patterns(scrape_bro_docs())
