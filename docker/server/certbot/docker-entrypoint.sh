#!/bin/sh

certbot renew

# wait 12 hours then quit
# docker should restart the container immediately which triggers the renew again
sleep 43200
