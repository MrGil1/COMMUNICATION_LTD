FROM mysql:8.0

ENV MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
ENV MYSQL_PASSWORD=${MYSQL_PASSWORD}


# Copy the initialization SQL script and the shell script to the Docker entrypoint directory
COPY ./init.sql /docker-entrypoint-initdb.d/
COPY ./init_database.sh /docker-entrypoint-initdb.d/

EXPOSE 3307

# Make the shell script executable
RUN chmod +x database/init_database.sh
RUN chmod +x database/init.sql
RUN chmod +x /docker-entrypoint-initdb.d/init_database.sh
RUN chmod +x /docker-entrypoint-initdb.d/init.sql


# Set the shell script as the entrypoint
ENTRYPOINT ["/docker-entrypoint-initdb.d/init_database.sh"]