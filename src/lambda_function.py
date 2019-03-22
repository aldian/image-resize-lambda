import base64
import hmac
import io
import json
import mimetypes
import os
import re
import uuid
from hashlib import sha1
from urllib import request

import boto3
import magic
from PIL import Image

PATH_RE = re.compile(r'^(?P<hash>[^/]+).*/(?P<width>\d+)x(?P<height>\d+)/(?P<original_path>.+)$')


def hmac_sha1(key_bytes, payload_bytes):
    """
    calculate hmac_sha1
    """
    return base64.urlsafe_b64encode(hmac.new(key_bytes, payload_bytes, sha1).digest())


def response_client_error(message):
    """
    Generate AWS lambda response object for client error
    """
    return {
        'statusCode': 400,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({
            'detail': message
        })
    }


def lambda_handler(event, context):
    """
    AWS will launch this function and passing two parameters:
    :param event: details of the request, including GET/POST parameters
    :param context: runtime information of this handler

    The detail about handler function function can be read here:
    https://docs.aws.amazon.com/lambda/latest/dg/python-programming-model-handler-types.html
    """

    params = event.get('queryStringParameters', {})
    image_path = params.get('key')
    if not image_path:
        return response_client_error('key is required')

    match = PATH_RE.match(image_path)
    if not match:
        return response_client_error('invalid image path format')

    passed_hash = match.group('hash')
    width = int(match.group('width'))
    height = int(match.group('height'))
    original_path = match.group('original_path')

    max_size = min(width, height)
    original_url = os.environ.get('URL') + original_path

    hmac_key = os.environ.get('THUMBNAIL_URL_SECURITY_KEY').encode('utf-8')
    hmac_payload = image_path.split('/', 1)[1].encode('utf-8')
    correct_hash = hmac_sha1(hmac_key, hmac_payload).decode()

    if passed_hash != correct_hash:
        return response_client_error('Invalid hash')

    try:
        file = io.BytesIO(request.urlopen(original_url).read())
        img = Image.open(file)
    except Exception as exc:
        return response_client_error(str(exc))

    original_width, original_height = img.size
    if max(original_width, original_height) > max_size:
        if original_width >= original_height:
            height = round(original_height * max_size / original_width)
            width = max_size
        else:
            width = round(original_width * max_size / original_height)
            height = max_size

        img.thumbnail((width, height), Image.ANTIALIAS)

    file_name = os.path.basename(original_path)
    content_type = mimetypes.guess_type(file_name)[0]
    if content_type is None:
        mime = magic.Magic(mime=True)
        content_type = mime.from_buffer(file)

    file_type = content_type.rsplit('/', 1)[1]

    folder = "/tmp/" + str(uuid.uuid4())
    os.makedirs(folder)
    local_thumbnail_path = os.path.join(folder, file_name)
    img.save(local_thumbnail_path, file_type)

    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get("S3_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("S3_SECRET_KEY"),
        )
        s3_client.upload_file(
            local_thumbnail_path, os.environ.get("BUCKET"),
            image_path,
            ExtraArgs={
                'ContentType': content_type, 'ACL': 'public-read'
            }
        )
    except Exception as exc:
        return response_client_error(str(exc))
    finally:
        os.remove(local_thumbnail_path)
        os.rmdir(folder)

    return {
        'statusCode': 301,
        'headers': {'Location': os.environ.get('URL') + image_path},
        'body': ''
    }
