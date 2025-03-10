#!/bin/bash
cd ..
./helper clean
cd project
make clean
cd ..
./helper compile