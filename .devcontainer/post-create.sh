#!/bin/sh

sudo usermod -a -G docker vscode

sudo apt-get update
sudo apt-get install -y postgresql-client

curl -sSL https://pdm-project.org/install-pdm.py | python3 -
