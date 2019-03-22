#!/bin/bash

coverage run --source="src" --omit="src/test*" src/test_lambda_function.py
coverage report -m
