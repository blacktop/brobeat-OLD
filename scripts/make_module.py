from jinja2 import Environment, PackageLoader
import json
import os

with open('bro-logs.json') as json_file:
    bro_logs = json.load(json_file)

env = Environment(loader=PackageLoader(__name__, 'templates'))

# create logstash config
template = env.get_template('logstash.conf')
logstash_dir = '../logstash/bro.conf'
with open('../logstash/bro.conf', 'w') as lsfile:
    lsfile.write(template.render(logs=bro_logs['logs']))

# create ingest pipelines
template = env.get_template('ingest/pipeline.json')
for log in bro_logs['logs']:
    ingest_dir = os.path.join('../module/bro', log['log_type'], 'ingest')
    if log.get('pattern', None):
        if not os.path.isdir(ingest_dir):
            os.makedirs(ingest_dir, 0755)
        with open(os.path.join(ingest_dir, 'no_plugins.json'), 'w') as plfile:
            plfile.write(template.render(log_file=log['file'],
                                         log_type=log['log_type'],
                                         pattern=log['pattern'].get('pattern')))
