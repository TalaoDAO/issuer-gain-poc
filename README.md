# issuer-gain-poc

generer key.json : 

1. Ouvrez un terminal.

2. Exécuter les commandes pour générer une clé privée EC P-256 et sa clé publique correspondante :

```bash
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

3. Utiliser la commande pour extraire les composantes X et Y de la clé publique :

```bash
openssl ec -pubin -in public_key.pem -text -noout
```

Return semblable à  :

```
read EC key
Private-Key: (256 bit)
priv:
    <la_composante_privée>
pub:
    X: <la_composante_x>
    Y: <la_composante_y>
```

4. Remplacer les valeurs dans le fichier `key.json` :

```json
{
  "issuer_private_key": {
    "kty": "EC",
    "crv": "P-256",
    "d": "<la_composante_privée>",
    "x": "<la_composante_x>",
    "y": "<la_composante_y>",
    "kid": "identifiant_de_clé"
  }
}
```

Conserver la clé privée (`private_key.pem`) et ne pas la partager. La clé publique peut être partagée et utilisée dans votre fichier `key.json`.