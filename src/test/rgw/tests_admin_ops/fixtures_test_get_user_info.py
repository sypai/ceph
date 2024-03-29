import pytest
import subprocess
import json
import hmac
import hashlib
import base64

# Constants
HOST = 'localhost:8000'
HTTP_REQUEST = 'GET'
CONTENT_TYPE = 'application/x-compressed-tar'
HTTP_QUERY = 'info'

# Fixtures
@pytest.fixture
def valid_user_id():
    """Fixture to provide a valid user ID."""
    return 'testid'

@pytest.fixture
def invalid_user_id():
    """Fixture to provide a invalid user ID."""
    return 'batman'

@pytest.fixture
def valid_resource():
    return '/admin/user'

@pytest.fixture
def invalid_resource():
    return '/admin'

@pytest.fixture
def valid_url(valid_user_id, valid_resource):
    return f'http://{HOST}{valid_resource}?{HTTP_QUERY}&uid={valid_user_id}'

@pytest.fixture
def url_with_invalid_resource(valid_user_id, invalid_resource):
    return f'http://{HOST}{invalid_resource}?{HTTP_QUERY}&uid={valid_user_id}'

@pytest.fixture
def url_with_invalid_user_id(invalid_user_id, valid_resource):
    return f'http://{HOST}{valid_resource}?{HTTP_QUERY}&uid={invalid_user_id}'

@pytest.fixture
def url_without_user_id(valid_resource):
    return f'http://{HOST}{valid_resource}?{HTTP_QUERY}'

@pytest.fixture
def url_with_access_key(valid_access_key, valid_resource):
    return f'http://{HOST}{valid_resource}?{HTTP_QUERY}&access-key={valid_access_key}'

@pytest.fixture
def url_with_format_xml(valid_user_id, valid_resource):
    return f'http://{HOST}{valid_resource}?{HTTP_QUERY}&uid={valid_user_id}&format=xml'

@pytest.fixture
def valid_dateTime():
    return subprocess.check_output(['date', '-u', '+%Y%m%dT%H%M%SZ']).decode('utf-8').strip()

@pytest.fixture
def invalid_dateTime():
    return '20240329 213433Z'

@pytest.fixture
def valid_access_key():
    return '0555b35654ad1656d804'

@pytest.fixture
def invalid_access_key():
    return 'batman'

@pytest.fixture
def valid_secret_key():
    """Fixture to provide a valid secret key."""
    return 'h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=='

@pytest.fixture
def invalid_secret_key():
    """Fixture to provide a invalid secret key."""
    return 'superman'

@pytest.fixture
def valid_signature(valid_secret_key, valid_dateTime, valid_resource):
    """Fixture to generate the request signature."""
    headerToSign = f"{HTTP_REQUEST}\n\n{CONTENT_TYPE}\n{valid_dateTime}\n{valid_resource}"
    signature = hmac.new(valid_secret_key.encode(), headerToSign.encode(), hashlib.sha1)
    return base64.b64encode(signature.digest()).decode()

@pytest.fixture
def signature_with_invalid_secret_key(invalid_secret_key, valid_dateTime, valid_resource):
    """Fixture to generate the request signature."""
    headerToSign = f"{HTTP_REQUEST}\n\n{CONTENT_TYPE}\n{valid_dateTime}\n{valid_resource}"
    signature = hmac.new(invalid_secret_key.encode(), headerToSign.encode(), hashlib.sha1)
    return base64.b64encode(signature.digest()).decode()

@pytest.fixture
def signature_with_invalid_datetime(valid_secret_key, invalid_dateTime, valid_resource):
    """Fixture to generate the request signature."""
    headerToSign = f"{HTTP_REQUEST}\n\n{CONTENT_TYPE}\n{invalid_dateTime}\n{valid_resource}"
    signature = hmac.new(valid_secret_key.encode(), headerToSign.encode(), hashlib.sha1)
    return base64.b64encode(signature.digest()).decode()

@pytest.fixture
def signature_with_invalid_http_method(valid_secret_key, valid_dateTime, valid_resource):
    """Fixture to generate the request signature."""
    headerToSign = f"POST\n\n{CONTENT_TYPE}\n{valid_dateTime}\n{valid_resource}"
    signature = hmac.new(valid_secret_key.encode(), headerToSign.encode(), hashlib.sha1)
    return base64.b64encode(signature.digest()).decode()

@pytest.fixture
def valid_header(valid_dateTime, valid_signature, valid_access_key):
    """Fixture to generate the request header."""
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Date': valid_dateTime,
        'Authorization': f'AWS {valid_access_key}:{valid_signature}',
        'Host': HOST
    }
    return headers

@pytest.fixture
def header_with_invalid_secret_key(valid_dateTime, signature_with_invalid_secret_key, valid_access_key):
    """Fixture to generate the request header."""
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Date': valid_dateTime,
        'Authorization': f'AWS {valid_access_key}:{signature_with_invalid_secret_key}',
        'Host': HOST
    }
    return headers

@pytest.fixture
def header_with_invalid_access_key(valid_dateTime, valid_signature, invalid_access_key):
    """Fixture to generate the request header."""
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Date': valid_dateTime,
        'Authorization': f'AWS {invalid_access_key}:{valid_signature}',
        'Host': HOST
    }
    return headers

@pytest.fixture
def header_with_invalid_dateTime(invalid_dateTime, valid_signature, valid_access_key):
    """Fixture to generate the request header."""
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Date': invalid_dateTime,
        'Authorization': f'AWS {valid_access_key}:{valid_signature}',
        'Host': HOST
    }
    return headers

@pytest.fixture
def header_with_invalid_http_method(valid_dateTime, signature_with_invalid_http_method, valid_access_key):
    """Fixture to generate the request header."""
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Date': valid_dateTime,
        'Authorization': f'AWS {valid_access_key}:{signature_with_invalid_http_method}',
        'Host': HOST
    }
    return headers


