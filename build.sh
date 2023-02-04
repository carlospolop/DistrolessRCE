#!/bin/bash

cd ./node/express-pp
docker build . -t dless-express-pp
minikube image load dless-express-pp
cd ../..

cd ./python/basic-http-rce
docker build . -t dless-python-rce
minikube image load dless-python-rce
cd ../..

cd ./python/flask-ssti
docker build . -t dless-flask-ssti
minikube image load dless-flask-ssti
cd ../..


