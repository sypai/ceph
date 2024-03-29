import pytest
import requests
from fixtures_test_get_user_info import *

# Tests
def test_get_user_info_success(valid_url, valid_header):
    """Test successful retrieval of user info."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=valid_header)
        assert response.status_code == 200
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_success_response(valid_url, valid_header):
    """Test successful retrieval of user info and response content."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=valid_header)
        assert response.status_code == 200
        data = response.json()
        assert 'user_id' in data
        assert 'display_name' in data
        assert 'suspended' in data
        assert 'max_buckets' in data
        assert 'subusers' in data
        assert 'keys' in data
        assert 'swift_keys' in data
        assert 'caps' in data
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_with_access_key(url_with_access_key, valid_header):
    """Test successful retrieval of user info with access key."""
    print(url_with_access_key)
    try:
        response = requests.get(url_with_access_key, headers=valid_header)
        assert response.status_code == 200
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_user_id(url_with_invalid_user_id, valid_header):
    """Test retrieval of user info with invalid user ID."""
    print(url_with_invalid_user_id)
    try:
        response = requests.get(url_with_invalid_user_id, headers=valid_header)
        assert response.status_code == 404
        expected_error_code = 'NoSuchUser'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_without_user_id(url_without_user_id, valid_header):
    """Test retrieval of user info without user ID."""
    print(url_without_user_id)
    try:
        response = requests.get(url_without_user_id, headers=valid_header)
        assert response.status_code == 400
        expected_error_code = 'InvalidArgument'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_resource(url_with_invalid_resource, valid_header):
    """Test retrieval of user info with invalid resource."""
    print(url_with_invalid_resource)
    try:
        response = requests.get(url_with_invalid_resource, headers=valid_header)
        assert response.status_code == 405
        expected_error_code = 'MethodNotAllowed'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_secret_key(valid_url, header_with_invalid_secret_key):
    """Test retrieval of user info with invalid secret key."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=header_with_invalid_secret_key)
        assert response.status_code == 403
        expected_error_code = 'SignatureDoesNotMatch'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_access_key(valid_url, header_with_invalid_access_key):
    """Test retrieval of user info with invalid access key."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=header_with_invalid_access_key)
        assert response.status_code == 403
        expected_error_code = 'InvalidAccessKeyId'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_dateTime(valid_url, header_with_invalid_dateTime):
    """Test retrieval of user info with invalid datetime."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=header_with_invalid_dateTime)
        assert response.status_code == 403
        expected_error_code = 'AccessDenied'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_invalid_http_method(valid_url, header_with_invalid_http_method):
    """Test retrieval of user info with invalid HTTP method."""
    print(valid_url)
    try:
        response = requests.get(valid_url, headers=header_with_invalid_http_method)
        assert response.status_code == 403
        expected_error_code = 'SignatureDoesNotMatch'
        assert response.json()['Code'] == expected_error_code
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

def test_get_user_info_response_content_type(url_with_format_xml, valid_header):
    """Test retrieval of user info with expected content type."""
    print(valid_url)
    try:
        response = requests.get(url_with_format_xml, headers=valid_header)
        assert response.status_code == 200
        assert response.headers.get('Content-Type', '') == 'application/xml'
    except requests.exceptions.RequestException as e:
        assert False, f"Request failed: {e}"

if __name__ == '__main__':
    pytest.main()
