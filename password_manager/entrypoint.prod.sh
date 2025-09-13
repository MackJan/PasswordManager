#!/bin/bash

if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."

    while ! nc -z $SQL_HOST $SQL_PORT; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

# Collect static files to the correct location
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate --noinput

exec "$@"
