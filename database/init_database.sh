#!/bin/bash
set -e

# Start MySQL server in the background
#mysqld_safe &

# Wait for MySQL to be ready
echo "Waiting for MySQL to start..."
until mysql -u root -p${MYSQL_ROOT_PASSWORD} -e "SELECT 1" > /dev/null 2>&1; do
    sleep 1
done

echo "MySQL is up and running."

# Run the init.sql script
mysql -u root -p${MYSQL_ROOT_PASSWORD} ${MYSQL_DATABASE} < /docker-entrypoint-initdb.d/init.sql

# Keep the container running
tail -f /dev/null