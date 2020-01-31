#!/bin/sh

docker run -ti --rm \
    --name postgrest \
    -p 8450:3000 \
    -e PGRST_DB_URI="postgres://${USER}@host.docker.internal/${USER}" \
    -e PGRST_DB_ANON_ROLE="${USER}" postgrest/postgrest
