# issuer-gain-poc


protocole openid vci 
norme draft 13

📝creer les metadata(contenu ,vc qu'on emet , quel contenu) celui de openid config test8 
le mettre sur un endpoints (
- endpoint /.well-known/credential_issuer_config
- endpoint /.well-known/openid-configuration
- endpoint /jwks
- endpoint /token
- endpoint /credential 

---
https://github.com/TalaoDAO/sandbox/blob/master/routes/oidc4vci_api.py:
app.add_url_rule("/issuer/<issuer_id>/token", view_func=issuer_token, methods=["POST"], defaults={"red": red, "mode": mode},)
app.add_url_rule("/issuer/<issuer_id>/credential", view_func=issuer_credential, methods=["POST"], defaults={"red": red, "mode": mode})


-----------------------------------------------------
📝-- reponse a la place jsonyfy

📝jwks = pub key , pas la private key 
📝clé p-256 au lieu de clé RSA

📝cherhcer doc erreur (ds le code) : 
 	client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        grant_type = request.form.get('grant_type')
        pre_authorized_code = request.form.get('pre_authorized_code')
        redirect_uri = request.form.get('redirect_uri')

token = clé en dure a mettre sur un fichier (pas sur le repo) ex key.json a insatller en ftp sur le server ,pour token

credentiel : site exemple talao.co


credentiel_offer = deja log au site = 'pre auth code flow'

creer offer sur le site (ou se trouve issuer pour recup meta, nom credential, pre atuh code 
+ pin code si need (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer)


https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata