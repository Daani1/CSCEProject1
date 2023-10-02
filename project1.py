# with the help of ChatGPT
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from urllib.parse import urlparse, parse_qs

hostName = "localhost"
serverPort = 8080

key_expiration_seconds = 2 * 60

# Dictionary to store key pairs and associated KIDs
key_pairs = {}

# Generate an RSA key pair with a unique KID
def generate_rsa_key_pair():
    # standard RSA key generaiton numbers
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    expiration_time = int(time.time()) + key_expiration_seconds  # Expiration in 2 minutes
    public_key = private_key.public_key()
    
    # Generate a KID for each key pair
    kid = "kid_" + str(int(time.time())) #using the time as the unique factor

    key_pairs[kid] = (private_key, public_key)

    return kid, expiration_time

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/auth":
            query_parameters = parse_qs(urlparse(self.path).query)# in order to handle the
            expired_param = query_parameters.get("expired")       # expired 

            self.send_response(200)
            self.send_header("Content-type", "application/jwt")  # Set the content type to JWT
            self.end_headers()

            if expired_param:
                # Generate JWT with an expired key pair and an expired expiration time
                kid, expired_expiration = generate_rsa_key_pair()
                payload = {
                    "sub": "1234567890",
                    "name": "John Doe",
                    "iat": int(time.time()),  # Use the current timestamp
                    "exp": expired_expiration  # Set the expired expiration time
                }
                private_key, _ = key_pairs[kid]
                jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": kid})
            else:
                # Generate JWT with an unexpired key pair
                kid, key_expiration = generate_rsa_key_pair()
                payload = {
                    "sub": "1234567890",
                    "name": "John Doe",
                    "iat": int(time.time()),  # Use the current timestamp
                    "exp": key_expiration  # Set the unexpired expiration time
                }
                private_key, _ = key_pairs[kid]
                jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": kid})

            self.wfile.write(jwt_token.encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #our JWK of JWTs
            keys = {
                "keys": []
            }

            # Include public keys from the key_pairs dictionary in the JWKS response
            for kid, (_, public_key) in key_pairs.items():
                # Serialize the public key to include in the JWKS response
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                keys["keys"].append({
                    "kid": kid,
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": public_key.public_numbers().n,
                    "e": public_key.public_numbers().e,
                    "x5c": [pem.decode("utf-8").replace("\n", "")]
                })#adding the key to the JWK

            dump = json.dumps(keys)
            self.wfile.write(bytes(dump, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":       
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
 
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
 
    webServer.server_close()
    print("Server stopped.")