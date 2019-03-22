# Image Resize Function for AWS Lambda

This lambda function is inspired by https://aws.amazon.com/solutions/serverless-image-handler/.
However, instead of using Thumbor, which is a big library/server, this function is simply using PIL.

When accessing image assets in the Amazon S3 bucket, users can specify the expected maximum size.
When the image that is smaller or equal to the specified size is not found, 
this AWS Lambda function will be executed to generate that image.

However, the resized image URL must be signed. Which means the URL cannot be generated by the end user. 
The signed URL must have been sent to the user at some point in the past, so later the user can load the image
using the signed URL.

## Installing requirements

This project is using `Python 3.6` and `virtualenv`.

`virtualenv` is required because the packaging script `create_dist.sh` rely on the environment variable `$VIRTUAL_ENV`.

From inside the `virtualenv`, execute `pip install -r requirements/base.txt`.

## Development

All activities described below are executed inside the `virtualenv`

### Installing development modules

Execute `pip install -r requirements/dev.txt`.

### Running unittest

Execute `./run_unit_test.sh`

## Deployment to AWS

### Uploading code

From inside the `virtualenv`, execute `./create_dist.sh`.

It will generate the `dist.zip` file.

Upload this file to the web console of the AWS lambda function.

### Add setting values to the environment variable

In the web console of the AWS lambda function, add these environment variables, and assign the correct values to it:
```
BUCKET=
URL=
S3_ACCESS_KEY_ID=
S3_SECRET_KEY=
THUMBNAIL_URL_SECURITY_KEY=
```

### Choose handler function

In the web console of the AWS lambda function, enter `lambda_function.lambda_handler` to the `Handler` field of
`Function code` section.
