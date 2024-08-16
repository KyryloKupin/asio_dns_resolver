#!/bin/bash
ab -n 10000 -c 1000 "http://localhost:8080/resolve?gmail.com&MX"
