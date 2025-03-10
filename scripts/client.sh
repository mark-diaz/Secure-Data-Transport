#!/bin/bash
CONTAINER_ID=$(docker ps -q --filter "name=project2_instance")
docker exec -it "$CONTAINER_ID" bash -c "cd /autograder/submission && ./client localhost 8080 && exec bash"

