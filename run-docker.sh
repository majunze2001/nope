#!/bin/bash
# run nope-container in interactive mode and mount this directory to home/reviewer/app
docker run -it --rm -v $(pwd):/home/reviewer/app -w /home/reviewer/app --platform linux/amd64 nope-container
