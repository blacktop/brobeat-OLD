from bs4 import BeautifulSoup
import requests
import json

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
        log['description'] = tds[1]
        log['fields'] = []
        bro_logs['logs'].append(log)

for log_type in bro_logs['logs']:
    if log_type.get('url'):
        resp = requests.get(url=log_type.get('url'))
        soup = BeautifulSoup(resp.content, "html.parser")
        for dt in soup.find_all("dt"):
            if '&log' in dt.text:
                log_type['fields'].append(dict(
                    field=dt.contents[0].split(':', 1)[0],
                    type=dt.contents[1].text))

with open('bro-logs.json', 'w') as jsonfile:
    json.dump(bro_logs, jsonfile)
