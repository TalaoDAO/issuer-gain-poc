import base64
import hashlib
import json
import logging
import math
import os
from datetime import datetime
from urllib.parse import parse_qs, urlparse
import qrcode
import requests
from flask import Flask, jsonify, request, send_file
from jwcrypto import jwk, jwt

logging.basicConfig(level=logging.INFO)
# app.logger.basicConfig(level=logging.INFO)

app = Flask(__name__)

# red = redis.Redis(host='localhost', port=6379, db=0)
# app.config['SESSION_TYPE'] = 'redis'

app.config['SESSION_TYPE'] = 'filesystem'


# Endpoint well-known/credential_issuer_config
@app.route('/.well-known/credential_issuer_config', methods=['GET'])
def well_known_credential_issuer_config():
    config = {
        "issuer": "https://talao.co/issuer/npwsshblrm",
        "name": "Credential Issuer",
        "description": "Issuer of Identity Credentials",
        "types_supported": ["IdentityCredential"],
        "credential_types_supported": [
            {
                "type": "IdentityCredential",
                "name": "Identity Credential",
                "description": "Credential for identity",
                "version": "1.0",
                "format": "vc+sd-jwt",
                "display": {
                    "name": "Identity Credential",
                    "text": "Your Identity Credential"
                }
            }
        ]
    }
    return jsonify(config)


# Endpoint well-known/openid-configuration @ https://talao.co/issuer/npwsshblrm/.well-known/openid-configuration
@app.route('/.well-known/openid-configuration', methods=['GET'])
def well_known_openid_configuration():
    config = {
        "authorization_endpoint": "https://talao.co/issuer/npwsshblrm/authorize",
        "credential_endpoint": "https://talao.co/issuer/npwsshblrm/credential",
        "credential_issuer": "https://talao.co/issuer/npwsshblrm",
        "credentials_supported": {
            "IdentityCredential": {
                "credential_definition": {
                    "vct": "https://credentials.example.com/identity_credential"
                },
                "cryptographic_binding_methods_supported": ["jwk", "x5c"],
                "cryptographic_suites_supported": ["ES256", "ES384", "ES512", "ES256K"],
                "display": [{"name": "Identity Credential"}],
                "format": "vc+sd-jwt",
                "proof_types_supported": ["jwt", "cwt"],
                "scope": "identity_credential"
            }
        },
        "deferred_credential_endpoint": "https://talao.co/issuer/npwsshblrm/deferred",
        "grant_types_supported": ["authorization_code"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "id_token_types_supported": ["subject_signed_id_token"],
        "request_authentication_methods_supported": {"authorization_endpoint": ["request_object"]},
        "request_object_signing_alg_values_supported": ["ES256", "ES256K", "EdDSA", "RS256"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_modes_supported": ["query"],
        "response_types_supported": ["vp_token", "id_token"],
        "scopes_supported": ["openid"],
        "subject_syntax_types_discriminations": ["did:key:jwk_jcs-pub", "did:ebsi:v1"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint", "did:key", "did:ebsi", "did:tz",
                                           "did:pkh", "did:hedera", "did:key", "did:ethr", "did:web", "did:jwk"],
        "subject_trust_frameworks_supported": ["ebsi"],
        "subject_types_supported": ["public"],
        "token_endpoint": "https://talao.co/issuer/npwsshblrm/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "vp_formats_supported": {
            "jwt_vc": {"alg_values_supported": ["ES256", "ES256K", "EdDSA", "RS256"]},
            "jwt_vp": {"alg_values_supported": ["ES256", "ES256K", "EdDSA", "RS256"]}
        }
    }
    return jsonify(config)


# Endpoint jwks
@app.route('/jwks', methods=['GET'])
def jwks():
    # Génére RSA pour signer les JWT
    key = jwk.JWK.generate(kty='RSA', size=2048)

    # Creer JSON Web Key Set (JWKS) avec la clé publique
    jwks = {
        "keys": [key.export(as_dict=True)]
    }
    return jsonify(jwks)


# Endpoint token
@app.route('/token', methods=['POST'])
def token_endpoint():
    try:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        grant_type = request.form.get('grant_type')
        pre_authorized_code = request.form.get('pre_authorized_code')
        redirect_uri = request.form.get('redirect_uri')

        pre_authorized_code = pre_authorized_code_user

        if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
            # Valide pre auth et retourne le token 
            access_token = validate_pre_authorized_code(client_id, client_secret, pre_authorized_code, redirect_uri)

            # Construit et retourne la réponse du jeton
            token_response = {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': 3600  # 1 hour
            }
            return jsonify(token_response)

        else:
            return jsonify({'error': 'Type de subvention non pris en charge'}), 400

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401  # 401 pour  erreurs d'auth

    except requests.exceptions.RequestException as re:
        logging.error(f"Erreur de réseau : {str(re)}")
        return jsonify({'error': 'Erreur de réseau'}), 500

    except Exception as e:
        logging.error(f"Erreur dans le point de terminaison /token : {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500



# Valide le code pré-auth
def validate_pre_authorized_code(client_id, client_secret, pre_authorized_code, redirect_uri):
    if pre_authorized_code:
        access_token = 'sample_access_token'
        return access_token
    else:
        raise Exception('Code pré-autorisé invalide')



# Endpoint credential
@app.route('/credential', methods=['POST'])
def credential_endpoint():
    try:
        data = request.get_json()
        credential_data = {
            'credential_type': data.get('credential_type'),
            'subject': data.get('subject'),
            'issuer': data.get('issuer'),
            # autre a add ??
        }

        response_data = {'message': 'La logique du point de terminaison /credential va ici', 'credential_data': credential_data}
        return jsonify(response_data)

    except Exception as e:
        logging.error(f"Erreur dans le point de terminaison /credential : {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500



                                                #Signature
#-------------------------------------------------------------------------------------------------
    
# Fonction pour signer un SD-JWT
def sign_sd_jwt(unsecured, issuer_key, issuer, subject_key):
    issuer_key = json.loads(issuer_key) if isinstance(issuer_key, str) else issuer_key
    _sd = []
    _disclosure = ""
        
    for claim in [attribute for attribute in unsecured.keys() if attribute != "vct"]:
        contents = json.dumps([salt(), claim, unsecured[claim]])
        disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
        _disclosure += "~" + disclosure
        _sd.append(hash(disclosure))
        
    signer_key = jwk.JWK(**issuer_key)
    pub_key = json.loads(signer_key.export(private_key=False))
    pub_key['kid'] = signer_key.thumbprint()
        
    header = {
        'typ': "vc+sd-jwt",
        'kid': pub_key['kid'],
        'alg': 'ES256'
    }
        
    payload = {
        'iss': issuer,
        'iat': math.ceil(datetime.timestamp(datetime.now())),
        'exp': math.ceil(datetime.timestamp(datetime.now())) + 10000,
        "_sd_alg": "sha256",
        "cnf": {
            "jwk": subject_key
        },
        "_sd": _sd,
        "vct": unsecured['vct'],
    }
        
    token = jwt.JWT(header=header, claims=payload, algs=['ES256'])
    token.make_signed_token(signer_key)
        
    return token.serialize() + _disclosure

def salt():
    return base64.urlsafe_b64encode(os.urandom(16)).decode().replace("=", "")

def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")

#-------------------------------------------------------------------------------------------------  

# Génére l'URI de l'offre de justif d'identité
def generate_credential_offer_uri():
    offer_endpoint = "https://trial.authlete.net/api/offer/issue"
    request_params = {
        "credentials": ["IdentityCredential"],
        "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}}
    }

    response = requests.post(offer_endpoint, json=request_params)
    response.raise_for_status()
    offer_data = response.json()
    credential_offer_uri = offer_data.get("credentialOfferUri")

    return credential_offer_uri

##Partie API @ https://trial.authlete.net/api/offer/issue
# Endpoint pour obtenir l'offre de justif d'idd
@app.route('/get_credential_offer', methods=['GET'])
def get_credential_offer():
    try:
        # URL de l'endpoint 
        offer_endpoint = "https://trial.authlete.net/api/offer/issue"

        print("Requesting credential offer")

        # Param de la requête
        request_params = {
            "credentials": ["IdentityCredential"],
            "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}}
        }

        # Envoi de la requête POST pour obtenir l'offre
        response = requests.post(offer_endpoint, json=request_params)
        response.raise_for_status()
        
        offer_data = response.json()
        credential_offer_uri = offer_data.get("credentialOfferUri")

        # Recup des données de l'URI
        uri_data = urlparse(credential_offer_uri)
        query_params = parse_qs(uri_data.query)
        pre_authorized_code = query_params.get('credential_offer_uri', [''])[0]

        # Génére un SD-JWT à partir de l'URI
        unsecured = {"vct": "https://credentials.example.com/identity_credential"}
        issuer_key = {"kty": "EC", "crv": "P-256", "x": "your_x", "y": "your_y"}
        issuer = "your_issuer"
        subject_key = {"kty": "EC", "crv": "P-256", "x": "subject_x", "y": "subject_y"}
        signed_sd_jwt = sign_sd_jwt(unsecured, issuer_key, issuer, subject_key)

        # Génére un QRcode à partir du SD-JWT
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(signed_sd_jwt)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save("./img_qrcode/credential_offer_qr.png")

        return jsonify({'success': True, 'credential_offer_uri': credential_offer_uri,
                        'pre_authorized_code': pre_authorized_code})

    except requests.exceptions.RequestException as re:
        logging.error(f"Erreur de réseau : {str(re)}")
        return jsonify({'error': 'Erreur de réseau', 'details': str(re)}), 500

    except requests.exceptions.HTTPError as he:
        logging.error(f"Erreur HTTP : {str(he)}")
        return jsonify({'error': 'Erreur lors de la demande d\'offre', 'details': str(he)}), 500

    except Exception as e:
        logging.error(f"Erreur lors de la demande d'offre : {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500


# Endpoint pour obtenir l'offre de justif d'idd
@app.route('/show_qr_code', methods=['GET'])
def show_qr_code():
    try:
        # Génére l'URI de l'offre de justif d'idd
        credential_offer_uri = generate_credential_offer_uri()

        # Config du code QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(credential_offer_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        image_stream = BytesIO()
        img.save(image_stream)
        image_stream.seek(0)

        # Renvoi en PNG
        return send_file(image_stream, mimetype='img_qrcode/png')

    except requests.exceptions.RequestException as re:
        return jsonify({'error': 'Erreur de réseau', 'details': str(re)}), 500

    except requests.exceptions.HTTPError as he:
        return jsonify({'error': 'Erreur lors de la demande d\'offre', 'details': str(he)}), 500

    except Exception as e:
        return jsonify({'error': 'Erreur interne du serveur'}), 500

##---------------------------------------------------------------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5000, debug=True)

    # Test well-known/credential_issuer_config (GET)
    response_config = requests.get('http://localhost:5000/.well-known/credential_issuer_config')
    print("Response from /.well-known/credential_issuer_config:")
    print(response_config.json())

    # Test well-known/openid-configuration (GET)
    response_openid_config = requests.get('http://localhost:5000/.well-known/openid-configuration')
    print("\nResponse from /.well-known/openid-configuration:")
    print(response_openid_config.json())

    # Test jwks (GET)
    response_jwks = requests.get('http://localhost:5000/jwks')
    print("\nResponse from /jwks:")
    print(response_jwks.json())

    # Test get_credential_offer (GET)
    response_get_credential_offer = requests.get('http://localhost:5000/get_credential_offer')
    print("\nResponse from /get_credential_offer:")
    print(response_get_credential_offer.json())

    # Extract pre_authorized_code from the response
    pre_authorized_code = response_get_credential_offer.json().get('pre_authorized_code', '')

    # Test token (POST)
    data_token = {
        'client_id': 'client_id',
        'client_secret': 'client_secret',
        'grant_type': 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre_authorized_code': pre_authorized_code,
        'redirect_uri': '/token'
    }

    response_token = requests.post('http://localhost:5000/token', data=data_token)
    print("\nResponse from /token:")
    print(response_token.json())

    # Test credential (POST)
    data_credential = {
        'credential_type': 'response_credential',
        'subject': 'subject',
        'issuer': 'issuer',
        # autre a add ??
    }

    response_credential = requests.post('http://localhost:5000/credential', json=data_credential)
    print("\nResponse from /credential:")
    print(response_credential.json())

