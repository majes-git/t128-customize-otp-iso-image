#!/bin/bash

tmpdir=$(mktemp -d) || exit 1
script=$(ls -1 *.py | sed -n '1s/\.py//p')
cp $script.py $tmpdir/__main__.py
python3 -m pip install -r requirements.txt --target $tmpdir
python3 -m zipapp --compress --python "/usr/bin/env python3" --output $script.pyz $tmpdir
rm -r $tmpdir
