"""Offline integration tests: exercise API behavior without pretending to contact networks."""
import json
import os
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app

FAKE_CLI = '''#!/usr/bin/env python3
import argparse
import csv
import sys
import time
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--no-color', action='store_true')
parser.add_argument('--print-all', action='store_true')
parser.add_argument('--csv', action='store_true')
parser.add_argument('--xlsx', action='store_true')
parser.add_argument('--txt', action='store_true')
parser.add_argument('--folderoutput')
parser.add_argument('--timeout', type=int)
parser.add_argument('--site', action='append', default=[])
parser.add_argument('--nsfw', action='store_true')
parser.add_argument('--local', action='store_true')
parser.add_argument('--ignore-exclusions', action='store_true')
parser.add_argument('username', nargs='+')
a=parser.parse_args()
out = Path(a.folderoutput)
out.mkdir(parents=True, exist_ok=True)
for username in a.username:
    print('[*] Checking username ' + username + ' on:', flush=True)
    print('[+] GitHub: https://github.com/' + username, flush=True)
    print('[-] Reddit: Not Found!', flush=True)
    print('[-] Uncertain: Blocked by bot detection (proxy may help)', flush=True)
    if username == 'slowuser': time.sleep(3)
    with (out / (username + '.csv')).open('w', newline='', encoding='utf-8') as f:
        w=csv.writer(f)
        w.writerow(['username','name','url_main','url_user','exists','http_status','response_time_s'])
        w.writerow([username,'GitHub','https://github.com','https://github.com/'+username,'Claimed','200','0.04'])
        w.writerow([username,'Reddit','https://reddit.com','https://reddit.com/u/'+username,'Available','404','0.08'])
        w.writerow([username,'Uncertain','https://invalid.example','https://invalid.example/u/'+username,'Unknown','',''])
    if a.txt:
        (out / (username + '.txt')).write_text('https://github.com/'+username+'\\n',encoding='utf-8')
    if a.xlsx:
        from openpyxl import Workbook
        wb=Workbook()
        ws=wb.active
        ws.append(['username','name'])
        ws.append([username,'GitHub'])
        wb.save(out / (username + '.xlsx'))
'''

class SherlockWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.script = self.folder / 'fake_sherlock'
        self.script.write_text(FAKE_CLI)
        self.script.chmod(0o755)
        self.env = patch.dict(os.environ, {'SHERLOCK_EXECUTABLE': str(self.script)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.scan_dir = patch.object(app, 'SCAN_DIR', self.folder / 'scans')
        self.scan_dir.start()
        self.addCleanup(self.scan_dir.stop)
        self.catalog_patch = patch.object(app, 'get_catalog', return_value={
            'entries': {'GitHub': {}, 'Reddit': {}, 'Uncertain': {'isNSFW': True}},
            'exclusions': {'Uncertain'}, 'source': 'fixture', 'fetched_at': 0
        })
        self.catalog_patch.start()
        self.addCleanup(self.catalog_patch.stop)
        self.client = TestClient(app.app)
        self.addCleanup(self.client.close)
        with app.JOBS_LOCK: app.JOBS.clear()

    def wait(self, job_id):
        for _ in range(100):
            r = self.client.get('/api/scans/' + job_id)
            if r.json()['status'] in ('completed', 'failed', 'cancelled'):
                return r.json()
            time.sleep(.05)
        self.fail('scan timed out')

    def test_homepage_and_meta(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertIn('Sherlock', self.client.get('/').text)
        self.assertIn('application/javascript', self.client.get('/assets/app.js').headers['content-type'])
        metadata = self.client.get('/api/meta').json()
        self.assertTrue(metadata['engine_ready'])
        self.assertEqual(metadata['site_count'], 2)
        self.assertEqual(metadata['catalog_count'], 3)
        site_list = self.client.get('/api/sites').json()
        self.assertEqual(len(site_list['sites']), 3)
        self.assertIn('Uncertain', site_list['nsfw'])
        self.assertIn('Uncertain', site_list['excluded'])

    def test_full_scan_multiple_names_and_exports(self):
        r = self.client.post('/api/scans', json={'usernames':['jane_doe','john_doe'], 'timeout':20,'sites':['GitHub']})
        self.assertEqual(r.status_code, 202, r.text)
        job = self.wait(r.json()['id'])
        self.assertEqual(job['status'], 'completed', job)
        for key, value in {'found':2,'not_found':2,'unknown':2,'checked':6,'target_sites':1}.items():
            self.assertEqual(job['summary'][key], value)
        self.assertEqual(len(job['results']), 6)
        self.assertTrue(any('GitHub' in line for line in job['log']))
        for ext in ('csv','json','txt','xlsx'):
            response = self.client.get(f'/api/scans/{job["id"]}/export/{ext}')
            self.assertEqual(response.status_code, 200, response.text[:100] if ext != 'xlsx' else 'xlsx download')
            self.assertTrue(response.content)
        self.assertEqual(len(json.loads(self.client.get(f'/api/scans/{job["id"]}/export/json').content)['results']), 6)
        self.assertIn('https://github.com/jane_doe', self.client.get(f'/api/scans/{job["id"]}/export/txt').text)
        self.assertEqual(len(self.client.get('/api/scans').json()), 1)

    def test_stop_scan(self):
        r = self.client.post('/api/scans', json={'usernames':['slowuser']})
        self.assertEqual(r.status_code, 202)
        scan_id = r.json()['id']
        time.sleep(.08)
        self.assertEqual(self.client.delete('/api/scans/' + scan_id).status_code, 200)
        job = self.wait(scan_id)
        self.assertEqual(job['status'], 'cancelled')
        self.assertGreaterEqual(len(job['results']), 1, 'Partial results should survive cancellation')
        self.assertTrue(any(item['site'] == 'GitHub' for item in job['results']))
        self.assertTrue(any(item['status'] == 'waf' for item in job['results']))

    def test_bad_names_and_missing_engine(self):
        bad = self.client.post('/api/scans', json={'usernames':['--proxy','okay']})
        self.assertEqual(bad.status_code, 422)
        with patch.dict(os.environ, {'SHERLOCK_EXECUTABLE':'/nonexistent/sherlock'}):
            r = self.client.post('/api/scans', json={'usernames':['good']})
            self.assertEqual(r.status_code, 503)

    def test_auth_token(self):
        with patch.object(app, 'AUTH_TOKEN', 'test-secret'):
            self.assertEqual(self.client.get('/api/scans').status_code, 401)
            self.assertEqual(self.client.get('/api/scans', headers={'X-Sherlock-Token':'test-secret'}).status_code, 200)

    def test_live_output_parsing(self):
        from pathlib import Path
        job = app.ScanJob('probe', app.ScanRequest(usernames=['demo']), self.folder)
        app.record_cli_event(job, '[*] Checking username demo on:')
        app.record_cli_event(job, '[+] GitHub: https://github.com/demo')
        app.record_cli_event(job, '[-] Reddit: Not Found!')
        app.record_cli_event(job, '[-] Discord: Blocked by bot detection (proxy may help)')
        self.assertEqual(len(job.results), 3)
        self.assertEqual([r['status'] for r in job.results], ['found','not_found','waf'])
        self.assertEqual(job.snapshot()['summary']['unknown'], 1)
        self.assertEqual(app.normalize_status('Illegal'), 'illegal')
        self.assertEqual(app.normalize_status('WAF'), 'waf')
        self.assertEqual(app.ScanRequest(usernames=['demo'], sites=['osu!']).sites, ['osu!'])

    def test_export_unknown_scan(self):
        self.assertEqual(self.client.get('/api/scans/nope/export/json').status_code, 404)
        self.assertEqual(self.client.delete('/api/scans/nope').status_code, 404)

if __name__ == '__main__': unittest.main()
