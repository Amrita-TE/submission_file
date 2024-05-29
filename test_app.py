import unittest
import json
from app import app
from datetime import datetime, timedelta
import pandas as pd
class TestCVEAPI(unittest.TestCase):

    @classmethod
    
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.client.testing = True

    def test_get_cves_no_filters(self):
        response = self.client.get('/api/cves')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(isinstance(data, list))

    def test_get_cves_with_cve_id(self):
        response = self.client.get('/api/cves?cve_id=CVE-1999-0095')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(all(cve['cve_id'] == 'CVE-1999-0095' for cve in data))

    def test_get_cves_with_year(self):
        response = self.client.get('/api/cves?year=1999')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(all(pd.to_datetime(cve['published_date']).year == 1999 for cve in data))

    def test_get_cves_with_score(self):
        response = self.client.get('/api/cves?score=10.0')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(all(cve['cvss_score'] == 10.0 for cve in data))

    def test_get_cves_with_days(self):
        response = self.client.get('/api/cves?days=30')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        threshold_date = datetime.now() - timedelta(days=30)
        self.assertTrue(all(pd.to_datetime(cve['last_modified_date']) >= threshold_date for cve in data))

if __name__ == '__main__':
    unittest.main()
