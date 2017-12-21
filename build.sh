#!/bin/bash
docker build -t lga-registry01.pulse.prod:5000/dex:pp . && docker push lga-registry01.pulse.prod:5000/dex:p
