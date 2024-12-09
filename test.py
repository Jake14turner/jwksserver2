import unittest
import sqlite3
import requests
import json
from datetime import datetime, timedelta

class TestJWKSAPI(unittest.TestCase):

    def setUp(self):

        self.db_conn = sqlite3.connect("test_privateKeys.db")
        self.cursor = self.db_conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                                key BLOB NOT NULL,
                                exp INTEGER NOT NULL)''')

        valid_key = "-----BEGIN PRIVATE KEY-----\nVALID_KEY\n-----END PRIVATE KEY-----"
        expired_key = "-----BEGIN PRIVATE KEY-----\nEXPIRED_KEY\n-----END PRIVATE KEY-----"
        valid_exp = int((datetime.utcnow() + timedelta(hours=1)).timestamp()) 
        expired_exp = int((datetime.utcnow() - timedelta(hours=1)).timestamp())  
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_key, valid_exp))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_key, expired_exp))
        self.db_conn.commit()

    def tearDown(self):
        self.cursor.close()
        self.db_conn.close()
        import os
        os.remove("test_privateKeys.db")

    def test_auth_valid_key(self):

        response = requests.post('http://127.0.0.1:8080/auth')
        self.assertEqual(response.status_code, 200)
        jwt = response.json().get('token')
        self.assertIsNotNone(jwt) 

    def test_auth_expired_key(self):
        response = requests.post('http://127.0.0.1:8080/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        jwt = response.json().get('token')
        self.assertIsNotNone(jwt)  

    def test_jwks_json(self):

        response = requests.get('http://127.0.0.1:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertTrue(len(jwks['keys']) > 0) 

if __name__ == '__main__':
    unittest.main()
