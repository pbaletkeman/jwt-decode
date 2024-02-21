async def decode_access_token(authorisation_token):
    import json
    from jose import jwt
    import httpx

    # get the algorithm type from the request header
    algorithm = jwt.get_unverified_header(authorisation_token).get('alg')

    unverified = jwt.get_unverified_claims(authorisation_token)

    server_url = unverified.get('iss') + '/.well-known/oauth-authorization-server'
    response = httpx.get(server_url)
    jwks_uri = {}
    if response.json():
        jwks_uri = response.json().get('jwks_uri')
    else:
        jwks_uri = json.loads(response.content).get('jwks_uri')

    # get public key from jwks uri
    response = httpx.get(jwks_uri)

    # gives the set of jwks keys.the keys has to be passed as it is to jwt.decode() for signature verification.
    key = response.json()

    options = {
        'verify_signature': False,
        'verify_aud': True,
        'verify_iat': True,
        'verify_exp': True,
        'verify_nbf': True,
        'verify_iss': True,
        'verify_sub': True,
        'verify_jti': True,
        'verify_at_hash': False,
        'require_aud': False,
        'require_iat': False,
        'require_exp': False,
        'require_nbf': False,
        'require_iss': False,
        'require_sub': False,
        'require_jti': False,
        'require_at_hash': False,
        'leeway': 0,
    }

    user_info = jwt.decode(token=authorisation_token,
                           audience=unverified.get('aud'),
                           issuer=unverified.get('iss'),
                           subject=unverified.get('sub'),
                           key=key,
                           algorithms=algorithm,
                           options=options
                           )

    return user_info
