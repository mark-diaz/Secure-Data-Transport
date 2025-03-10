#!/bin/bash
CONTAINER_ID=$(docker ps -q --filter "name=project2_instance")
docker exec -it "$CONTAINER_ID" bash -c \
    "cd /autograder/source/keys && \
    ./gen_files && \
    ./../../submission/server 8080 && \
    exec bash"