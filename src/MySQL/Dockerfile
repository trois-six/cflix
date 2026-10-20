FROM mysql:9.7
COPY "./SQL_Scripts/*" /docker-entrypoint-initdb.d/
ENV MYSQL_DATABASE=cflixdb