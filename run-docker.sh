#!/bin/bash
# run nope-container in interactive mode and mount this directory to home/reviewer/app
docker run -it --rm \
  --platform linux/amd64 \
  -v $(pwd):/home/reviewer/app \
  -w /home/reviewer/app \
  --name nope \
  nope-container
