# CFlix

CFlix is a Netflix-like website used as a hands-on security challenge: some
flaws have been deliberately introduced and exploited by a malicious hacker
(**hackonymousoflix**). Solve all the available challenges to win.

## Try CFlix yourself

To keep the different challenges safe, CFlix is a Docker-based project with the
following architecture:

- core projects:
  - CFlix -> the main website
  - CFlix.ImageViewer -> a website dedicated to a directory-traversal challenge
  - PostgreSQL -> the main database (holds participant information)
  - MySQL -> the main database of the CFlix site data used by the challenges (no critical user information in it)
- support projects:
  - Nginx -> used as a reverse-proxy to expose CFlix and CFlix.ImageViewer over HTTPS
  - Redis -> used only to persist user sessions server-side (so the other containers can be restarted)
- last challenges:
  - hackonymousoflix -> container with the last four challenges
  - shop.hackdumb.com -> the ultimate challenge

If you want to use CFlix in your organization, you can plug in an Active
Directory (or any LDAP). See the [configuration section](#configuration) to
learn how.

### Configuration

You can tweak a few settings in `docker-compose.yml` or in `appsettings.json`.

1. **LDAP**: to use Active Directory or LDAP, set `CFLIX__USELDAP` to `true` and
   `ConnectionStrings__LdapUrl` to your LDAP URL. To check whether a user can log
   into CFlix, we try the submitted credentials against the LDAP (so you do not
   need any system credentials). You can also set `CFLIX__LDAPDOMAIN` to prefix
   an NT/LDAP domain to the username.
2. **Redis**: to disable Redis (for example to debug CFlix locally), add
   `CFLIX__USEREDIS=false`.
3. **Stage**: CFlix has three stages (each stage unlocks some challenges).

### Build and launch

After tweaking the configuration, run:

```bash
docker compose build
docker compose up -d
docker compose exec cflix dotnet CFlix.dll database update all
```

Then browse to <https://localhost>.

## Development

### Database schema

The database schema is provisioned by the SQL init scripts under
`../Postgres/SQL_Scripts` and `../MySQL/SQL_Scripts` (they also pre-populate
`__EFMigrationsHistory`). The EF Core migrations were therefore removed during
the .NET 10 modernization; the app relies on `EnsureCreated` plus those scripts.

### Seed the database

To run the schema creation and seed the data:

```bash
dotnet CFlix.dll database update all
# or independently:
dotnet CFlix.dll database update mysql
dotnet CFlix.dll database update postgres
```

### Front-end assets

The front-end libraries (jQuery, Semantic UI, moment, ...) are served from a CDN
with a local fallback to the committed assets, so no `bower` / bundler build step
is required.
