from flask import Flask, jsonify, Response
import requests
from flask_session import Session
import redis
import uuid

ACCESS_TOKEN_LIFE = 10000
C_NONCE_LIFE = 5000

# Endpoint pour obtenir un jeton
# @app.route('/get_token', methods=['GET'])
# def get_token():
#     client_id = "client_id"  # Remplacez par votre véritable client_id
#     client_secret = "client_secret"  # Remplacez par votre véritable client_secret
#     grant_type = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
#     pre_authorized_code = "dNabZC7KIa2t3LIyTPeGFpc7r7QIjcuMYN_ACc2Wm28"
#     redirect_uri = "/token"

#     # Demande de jeton à l'émetteur d'identité
#     token_url = "http://127.0.0.1:5000/issuer/token"  # Remplacez par l'URL correcte
#     data = {
#         'client_id': client_id,
#         'client_secret': client_secret,
#         'grant_type': grant_type,
#         'pre_authorized_code': pre_authorized_code,
#         'redirect_uri': redirect_uri
#     }

#     response = requests.post(token_url, data=data)
#     return response.text, response.status_code

# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Init Flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY = "lkjhlkjh" # your application secret code for session, random
)

# Framework Flask and Session setup
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100

sess = Session()
sess.init_app(app)


@app.route('/', methods=['GET', 'POST'])
def hello():
    return jsonify("hello")


# exemple endpointy
@app.route('/endpoint1')
def endpoin1t():    
    json_response = {
       "key" : "value"
   }
    return jsonify(json_response) 


# exemple config openid pour issuer
@app.route("/.well-known/openid-credential-issuer", methods=["GET"])
def issuer_openid_configuration():
    issuer_openid_configuration = {}
    issuer_openid_configuration.update(
        {
            "credential_issuer":  "/issuer",
            "token_endpoint":  "/issuer/token",
            "credential_endpoint": "issuer/credential",
        }
    )
    return jsonify(issuer_openid_configuration)



# exemple token ednpoint
@app.route('/issuer/token', methods=["POST"])
def token():    
     # token endpoint response
    access_token = str(uuid.uuid1())
    endpoint_response = {
        "access_token": access_token,
        "c_nonce": str(uuid.uuid1()),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE,
    }
    headers = {
         "Cache-Control": "no-store",
        "Content-Type": "application/json"}
    return Response(response=json.dumps(endpoint_response), headers=headers)



if __name__ == '__main__':
    app.run( host = "127.0.0.1", port=5000, debug =True)
