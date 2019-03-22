import base64
import unittest
import uuid
from unittest.mock import MagicMock, patch

from ddt import ddt, data, unpack

import lambda_function


image_url_prefix = "https://{}.com/".format(uuid.uuid4())
thumbnail_url_security_key = str(uuid.uuid4())
s3_access_key_id = str(uuid.uuid4())
s3_secret_key = str(uuid.uuid4())
s3_bucket_name = str(uuid.uuid4())


def mock_environ_get(key):
    """
    Mock some environment variables for testing
    """
    if key == 'URL':
        return image_url_prefix

    if key == 'THUMBNAIL_URL_SECURITY_KEY':
        return thumbnail_url_security_key

    if key == 'S3_ACCESS_KEY_ID':
        return s3_access_key_id

    if key == 'S3_SECRET_KEY':
        return s3_secret_key

    if key == 'BUCKET':
        return s3_bucket_name


def mock_image_open_big_landscape(file):
    """
    Mock opening big image
    """
    img = MagicMock()
    img.size = (1000, 700)
    return img


def mock_image_open_big_portrait(file):
    """
    Mock opening big image
    """
    img = MagicMock()
    img.size = (700, 1000)
    return img


def mock_Magic(mime=None):
    """
    Mock file type investigation
    """
    mime = MagicMock()
    mime.from_buffer = MagicMock(return_value='image/png')
    return mime


def mock_boto_client_upload_success(*args, **kwargs):
    """
    Mock boto client, so uploading always returns success
    """
    return MagicMock()


def mock_boto_client_upload_failed(*args, **kwargs):
    """
    Mock boto client, so uploading is always failed
    """
    boto_client = MagicMock()
    boto_client.upload_file = MagicMock(side_effect=Exception("Upload to S3 failed"))
    return boto_client


@ddt
class LambdaFunctionTests(unittest.TestCase):
    """
    Test functions in lambda_function.py
    """
    @data(
        ["", "", b"\xfb\xdb\x1d\x1b\x18\xaa\x6c\x08\x32\x4b\x7d\x64\xb7\x1f\xb7\x63\x70\x69\x0e\x1d"],
        [
            "key", "The quick brown fox jumps over the lazy dog",
            b"\xde\x7c\x9b\x85\xb8\xb7\x8a\xa6\xbc\x8a\x7a\x36\xf7\x0a\x90\x70\x1c\x9d\xb4\xd9"
        ]
    )
    @unpack
    def test_hmac_sha1(self, key, payload, expected_digest):
        """
        At https://en.wikipedia.org/wiki/HMAC,
        there are two examples of the results of hmac-sha1:
        HMAC_SHA1("", "")   = fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
        HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog") = de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
        """
        self.assertEqual(
            base64.urlsafe_b64encode(expected_digest),
            lambda_function.hmac_sha1(key.encode('utf-8'), payload.encode('utf-8'))
        )

    def test_lambda_handler_key_not_specified(self):
        """
        When the call doesn't specify key containing the requested image path,
        it returns error
        """
        response_obj = lambda_function.lambda_handler({}, None)
        self.assertEqual(400, response_obj['statusCode'])

    def test_lambda_handler_invalid_format(self):
        """
        When the requested image path doesn't follow a specific format: width x height/filename
        it returns error
        """
        event = {
            'queryStringParameters': {
                'key': 'mama'
            }
        }
        response_obj = lambda_function.lambda_handler(event, None)
        self.assertEqual(400, response_obj['statusCode'])

    @patch('os.environ.get')
    def test_lambda_handler_invalid_hash(self, environ_get):
        """
        When hash is not a valid hmac-sha1 calculation,
        it returns error
        """
        environ_get.side_effect = mock_environ_get

        event = {
            'queryStringParameters': {
                'key': 'HASH/fit-in/400x400/cat.jpg'
            }
        }
        response_obj = lambda_function.lambda_handler(event, None)
        self.assertEqual(400, response_obj['statusCode'])

    @patch('urllib.request.urlopen')
    @patch('os.environ.get')
    def test_lambda_handler_fail_loading_original_image(self, environ_get, urlopen):
        """
        When the original image cannot be read from S3,
        it should return error 400
        """
        environ_get.side_effect = mock_environ_get
        urlopen.side_effect = Exception("Not found")

        security_key = environ_get("THUMBNAIL_URL_SECURITY_KEY")
        payload = 'fit-in/400x400/cat.jpg'
        signature = lambda_function.hmac_sha1(security_key.encode("utf-8"), payload.encode("utf-8")).decode()
        event = {
            'queryStringParameters': {
                'key': signature + '/' + payload
            }
        }
        response_obj = lambda_function.lambda_handler(event, None)
        self.assertEqual(400, response_obj['statusCode'])

    @data(
        [mock_image_open_big_landscape, 'fit-in/400x400/cat.jpg', mock_boto_client_upload_success, 301],
        [mock_image_open_big_portrait, 'fit-in/400x400/cat', mock_boto_client_upload_failed, 400]
    )

    @unpack
    @patch('os.remove')
    @patch('io.BytesIO')
    @patch('urllib.request.urlopen')
    @patch('boto3.client')
    @patch('magic.Magic')
    @patch('PIL.Image.open')
    @patch('os.environ.get')
    def test_lambda_handler_upload(
            self, mock_image_open, payload, mock_upload_file, status_code,
            environ_get, image_open, Magic, boto_client, *args
    ):
        """
        Test uploading the generated thumbnail to S3.
        When successful, it should redirect (301) the browser back to the signed S3 URL.
        When failed, it should return 400 error status.
        """
        environ_get.side_effect = mock_environ_get
        image_open.side_effect = mock_image_open
        Magic.side_effect = mock_Magic
        boto_client.side_effect = mock_upload_file

        security_key = environ_get("THUMBNAIL_URL_SECURITY_KEY")
        signature = lambda_function.hmac_sha1(security_key.encode("utf-8"), payload.encode("utf-8")).decode()
        event = {
            'queryStringParameters': {
                'key': signature + '/' + payload
            }
        }
        response_obj = lambda_function.lambda_handler(event, None)
        self.assertEqual(status_code, response_obj['statusCode'])


if __name__ == '__main__':
    unittest.main()
