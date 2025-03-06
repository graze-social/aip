#!/bin/sh
echo "Waiting for database connection..."
until pg_isready -h db -p 5432 -U aip; do
  sleep 2
done
echo "Database is ready."

# Ensure the database exists
echo "Checking if database exists..."
DB_EXISTS=$(PGPASSWORD="aip_password" psql -h db -U aip -tAc "SELECT 1 FROM pg_database WHERE datname='aip_db'")
if [ "$DB_EXISTS" != "1" ]; then
  echo "Database aip_db not found, creating..."
  PGPASSWORD="aip_password" createdb -h db -U aip aip_db
else
  echo "Database already exists."
fi

# Generate signing keys if they don't exist
if [ ! -f signing_keys.json ]; then
  echo "Generating signing keys..."
  SIGNING_KEY=$(pdm run aiputil gen-jwk)
  if [ -n "$SIGNING_KEY" ]; then
    echo "{\"keys\":[$SIGNING_KEY]}" > signing_keys.json
    echo "Signing keys generated."
  else
    echo "Error generating signing keys!"
    exit 1
  fi
else
  echo "Signing keys already exist."
fi

# Extract 'kid' values from signing_keys.json
if command -v jq >/dev/null 2>&1; then
  export ACTIVE_SIGNING_KEYS=$(jq -c '[.keys[].kid]' signing_keys.json)
else
  echo "Error: jq is required but not installed. Install jq to continue."
  exit 1
fi

# Run Alembic migrations
echo "Running Alembic migrations..."
pdm run alembic upgrade head || { echo "Alembic migrations failed!"; exit 1; }

# Start the AIP server
echo "Starting AIP server..."
sleep infinity
exec pdm run aipserver
