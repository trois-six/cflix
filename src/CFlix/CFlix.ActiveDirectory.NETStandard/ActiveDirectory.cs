using Novell.Directory.Ldap;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CFlix.ActiveDirectory.NETStandard
{
    public class ActiveDirectory : IDisposable
    {
        private LdapConnection connection;
        private readonly Uri adUri;

        public ActiveDirectory(string activeDirectoryUri)
            :this( string.IsNullOrEmpty(activeDirectoryUri)? null : new Uri(activeDirectoryUri))
        {
        }

        public ActiveDirectory(Uri activeDirectoryUri)
        {
            connection = new LdapConnection();
            adUri = activeDirectoryUri;
        }

        public async Task<ActiveDirectoryUser> AuthenticateUserAsync(string username, string password)
        {
            try
            {
                await connection.ConnectAsync(adUri.Host, adUri.Port);

                try
                {
                    await connection.BindAsync(username, password);
                }
                catch (LdapException e) when (e.ResultCode == LdapException.InvalidCredentials)
                {
                    return null;
                }

                return await SearchUserAsync(username);
            }
            finally
            {
                password = null;
                connection.Disconnect();
            }
        }

        private async Task<ActiveDirectoryUser> SearchUserAsync(string username)
        {
            var currentUser = new ActiveDirectoryUser();

            var lsc = await connection.SearchAsync(
                adUri.AbsolutePath.Substring(1),
                LdapConnection.ScopeSub,
                $"(sAMAccountName={(username.Contains("\\") ? username.Split('\\').Last() : username)})",
                new[] { "name", "userPrincipalName", "sAMAccountName", "employeeID", "extensionAttribute1" },
                false);

            await foreach (var nextEntry in lsc)
            {
                currentUser.Name = nextEntry.GetStringValueOrDefault("name");
                currentUser.Email = nextEntry.GetStringValueOrDefault("userPrincipalName");
                currentUser.NameIdentifier = nextEntry.GetStringValueOrDefault("sAMAccountName");
                currentUser.EmployeeID = nextEntry.GetStringValueOrDefault("employeeID");

                return currentUser;
            }

            return null;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    connection.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}