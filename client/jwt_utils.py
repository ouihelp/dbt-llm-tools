import json
from datetime import datetime

from dateutil.tz import tzutc
from jwcrypto.jwt import JWT, JWTExpired, JWTMissingKey
from jwcrypto.jwk import JWKSet
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature
import requests
from werkzeug.http import parse_date


jwk_uri = "https://www.googleapis.com/oauth2/v3/certs"

google_key_set = None


def get_google_key_set():
    global google_key_set

    if google_key_set is None or google_key_set[0] < datetime.now(tzutc()):
        request = requests.get(jwk_uri, timeout=3)

        raw_expires_at = parse_date(request.headers["expires"])
        assert raw_expires_at
        expires_at = raw_expires_at.replace(tzinfo=tzutc())

        google_key_set = (expires_at, JWKSet.from_json(request.text))

    return google_key_set[1]


def process_jwt_payload(payload, key):
    """Process a JWT payload (usually a string) and return a JWT object
    if the process went fine.

    """
    try:
        return JWT(
            key=key,
            jwt=payload,
            check_claims={"exp": None},  # Weird syntax but it says
            # "Check expiration time"
            algs=["ES256", "ES384", "ES521", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
        )
    except InvalidJWSObject:
        raise Exception("InvalidPayload")
    except JWTExpired:
        raise Exception("ExpiredToken")
    except JWTMissingKey:
        raise Exception("MissingKey")
    except InvalidJWSSignature:
        raise Exception("InvalidSignature")


def extract_claims_jwt(payload):
    key = get_google_key_set()

    jwt = process_jwt_payload(payload, key)

    claims = json.loads(jwt.claims)

    if claims["hd"] != "ouihelp.fr":
        raise Exception("WrongHostedDomain")

    return claims
