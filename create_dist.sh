#!/bin/bash

rm -rf dist
rm dist.zip
mkdir dist
cp -a src/*.py dist
cp -a $VIRTUAL_ENV/lib/python3.6/site-packages/* dist
rm -rf dist/__pycache__
rm -rf dist/boto*
rm -rf dist/certifi*
rm -rf dist/chardet*
rm -rf dist/coverage*
rm -rf dist/dateutil
rm -rf dist/ddt*
rm -rf dist/docutils*
rm -rf dist/easy_install.py
rm -rf dist/idna*
rm -rf dist/jmespath*
rm -rf dist/pip*
rm -rf dist/pkg_resources
rm -rf dist/python_dateutil*
rm -rf dist/s3transfer*
rm -rf dist/setuptools*
rm -rf dist/six*
rm -rf dist/test_*.py
rm -rf dist/urllib3*
rm -rf dist/wheel*
rm -rf dist/PIL/__pycache__
cd dist
zip -r ../dist.zip *
cd ..
