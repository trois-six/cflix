using CFlix.ActiveDirectory.NETStandard;
using CFlix.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CFlix.Services
{
    public class CFlixSignInManager : SignInManager<CFlixUser>
    {
        private CFlix.ActiveDirectory.NETStandard.ActiveDirectory ad;

        public CFlixSignInManager(UserManager<CFlixUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<CFlixUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<CFlixUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<CFlixUser> confirmation,
            CFlix.ActiveDirectory.NETStandard.ActiveDirectory directory)
            : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
            ad = directory;
        }

        public async override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            // Optional NT/LDAP domain prefix, configurable through CFLIX__LDAPDOMAIN
            // (left empty by default so the project stays organization-agnostic).
            var domain = Environment.GetEnvironmentVariable("CFLIX__LDAPDOMAIN");
            var login = string.IsNullOrEmpty(domain) ? userName : domain + "\\" + userName;
            var userAd = await ad.AuthenticateUserAsync(login, password);

            if (userAd != null)
            {
                var availableUser = await UserManager.FindByNameAsync(userAd.NameIdentifier);

                if (availableUser != null)
                {
                    await SignInAsync(availableUser, isPersistent);
                    return SignInResult.Success;
                }
                else
                {
                    var usr = new CFlixUser
                    {
                        UserName = userAd.NameIdentifier,
                        Email = userAd.Email,
                        EmployeeID = userAd.EmployeeID,
                        DisplayName = userAd.Name
                    };

                    //usr.Claims.Add(new Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityUserClaim<string>
                    //{
                    //    ClaimType = "DisplayName",
                    //    ClaimValue = userAd.Name
                    //});

                    var result = await UserManager.CreateAsync(usr);
                    if (result.Succeeded)
                    {
                        await SignInAsync(usr, isPersistent);
                        return SignInResult.Success;
                    }
                }
            }

            return await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
        }
    }
}
