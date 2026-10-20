# CFlix - Deployment

## Project layout

The solution is split into nine containers.

- The ones that make up the CFlix site
  - **CFlix**: the main website
  - **CFlix.ImageViewer**: an API used by one of the challenges, called from the CFlix container
  - **Postgres**: the project's main database, holding all the critical information (user logins, found easter eggs, ...)
  - **MySQL**: the secondary database, holding the site data related to the challenges (available TV shows and comments). It is used by one of the challenges (SQLi)
  - **Redis**: lets the CFlix container restart without losing user sessions (and allows scaling the front-end containers)
- The ones belonging to the hacker Hackonymousoflix
  - **Hackonymousoflix**: the container representing the attacker's server
  - **RobotShop**: the container representing Hackonymousoflix's online shop
  - **ShoxxBot**: the container simulating the RobotShop administrator
- The ones exposing the web services to the outside
  - **Reverse-proxy**: an nginx container exposing CFlix over HTTPS. It is also used to expose the Hackonymousoflix container over HTTPS.

The `docker-compose.yml` file describes the orchestration between these services.

NB: the `docker-compose.override.yml` file is used by the Visual Studio extension for debugging.

NB 2: the `docker-compose.opendbport.yml` file can be used to start the stack with the database ports open (for example to run analytics on the participants).

## Configuration

To make it easier to reuse the project in other environments, a number of
settings are available to tweak its configuration.

### Environment variables of the **CFlix** container

The following settings are available if you want to reuse the CFlix container in
another context.

- Connection strings:
  - `CONNECTIONSTRINGS__DEFAULTCONNECTION` — connection string to the PostgreSQL database
  - `CONNECTIONSTRINGS__CFLIXCONNECTION` — connection string to the MySQL database
  - `CONNECTIONSTRINGS__CFLIXROCONNECTION` — secondary connection string to the MySQL database (/!\ it must point to the same host as the previous one but with a read-only account, as it is used for the SQL injection challenge)
  - `CONNECTIONSTRINGS__LDAPURL` — connection string to the Active Directory / LDAP to use
  - `CONNECTIONSTRINGS__REDIS` — connection string to the Redis database (used only for caching)
  - `CFLIX__IMAGEAPI` — URL of the CFlix.ImageViewer service used by the LFI challenge
  - `CFLIX__HACKONYMOUSOFLIXDOMAIN` — domain name pointing to the hackonymousoflix service
- Behavior settings:
  - `CFLIX__USELDAP` — boolean enabling or disabling the use of LDAP (see below)
  - `CFLIX__USEREDIS` — boolean enabling or disabling the use of Redis
  - `CFLIX__LDAPDOMAIN` — optional NT/LDAP domain prefixed to the username when authenticating (empty by default, so the project stays organization-agnostic)
  - `CFLIX__STAGE` — 1, 2 or 3, matching the different phases available (see below)

### Using LDAP

CFlix can authenticate players against an Active Directory / LDAP, which is
useful if you want to identify who is solving the challenges.

To enable it, set the `CFLIX__USELDAP` and `CONNECTIONSTRINGS__LDAPURL`
variables (and optionally `CFLIX__LDAPDOMAIN`).

### Stages

The challenges are grouped into three stages, so you can unlock them
progressively instead of exposing everything at once.

To move from one stage to the next, bump the `CFLIX__STAGE` variable from 1 to 3
and run a database update on the PostgreSQL database to insert the new
challenges.

NB: going back to an earlier stage does not disable the challenges, even after a
fresh database migration (you first have to drop the databases for that).
