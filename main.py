from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import jwt
import json
import rsa 
import base64
import sqlite3
import os

app = Flask(__name__)


DB_NAME = 'totally_not_my_privateKeys.db'

#intiail funciton to get the database setup
def init_db():
    """Initialize the SQLite database and create the keys table if it doesn't exist."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        conn.commit()


#this will be called to get the public and private keys and put them into the database. 
def load_or_generate_keys():
    """Load private and public keys from the database, or generate new ones if they don't exist."""
    with sqlite3.connect(DB_NAME) as conn: #connect to the database
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.utcnow().timestamp()),))
        row = cursor.fetchone()
        
        if row:
            private_key = row[0]  #retrieve the private key from the database
            public_key = rsa.PublicKey.load_pkcs1(private_key).save_pkcs1()
            return private_key, public_key
        else:
            #generate new keys and save them to the database
            (public_key, private_key) = rsa.newkeys(2048)
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                           (private_key.save_pkcs1(), int((datetime.utcnow() + timedelta(days=365)).timestamp())))
            conn.commit()
            return private_key.save_pkcs1(), public_key.save_pkcs1()


init_db() 
private_key, public_key = load_or_generate_keys()

#function to base64url encode a number
def base64url_encode(value):
    """Encodes a value to base64url."""
    return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')

#define jwt's
JWK_KEYS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256", 
            "kid": "unique-key-id",  
            "use": "sig",
            "n": base64url_encode(rsa.PublicKey.load_pkcs1(public_key).n),
            "e": base64url_encode(65537) 
        }
    ]
}

#auth endpoint
@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    password = request.json.get('password')
    expired = request.args.get('expired')  #check for 'expired' query parameter

    if username == 'userABC' and password == 'password123':
        #determine expiration time based on the 'expired' parameter
        if expired == 'true':
            #if someone is requesting an expired key, then set the expiration date 10 mins in the past. 
            expiration = datetime.utcnow() - timedelta(minutes=10)
        else:
            #set 10 min expiration
            expiration = datetime.utcnow() + timedelta(minutes=10)

        headers = {"kid": "unique-key-id"}
        token = jwt.encode({'exp': expiration}, private_key, algorithm='RS256', headers=headers)#encode the token
        return jsonify(token=token), 200 
    else:
        return jsonify({"message": "Invalid credentials"}), 401

#other endpoint that returns list of keys. 
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(JWK_KEYS), 200

#endpoint to decode key
@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    token = request.headers.get('Authorization').split()[1] #someone can enter their code and if its correct, decode the token and print out the payload.
    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({"message": "Token is valid", "payload": payload}), 200
    except jwt.ExpiredSignatureError: #if the token is expired then let them know
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError: #if they type the token incorrectly thn let them know. 
        return jsonify({"message": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(port=8080)
