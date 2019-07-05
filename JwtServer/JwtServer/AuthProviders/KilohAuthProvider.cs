using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JwtSecurityContracts.DtoClasses;
using JwtServer.Infrastructure;
using JwtServer.Infrastructure.Internal;
using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json;
using QueryObjects;
using QueryObjects.Queries;
using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace JwtServer.AuthProviders
{
    public static class KilohAuthProvider
    {

        //Custom Claim Types
        public const string UserIDClaimType = "KilohApp/UserId";
        public const string RoleClaimType = "KilohApp/SystemRole";
        public const string ClientIdClaimType = "KilohApp/ClientId";
        public const string UserEmailClaimType = "KilohApp/UserEmail";

        //delegate for validating the grant type and client are supplied and correct
        public static Func<ValidateTokenRequestContext, Task> ValidateTokenRequest = (context) =>
        {
            // Reject token requests that don't use grant_type=password or grant_type=refresh_token
            //or grant_type=client_credentials
            if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType()
               && !context.Request.IsClientCredentialsGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only grant_types password, refresh_token and client_credentials " +
                                 "are accepted by this server.");

                return Task.CompletedTask;
            }

            // parameter is missing to support unauthenticated token requests.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                context.Reject(
                   error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                   description: "client id was not supplied - request rejected.");

                return Task.CompletedTask;
            }

            //validate the clientId and clientSecret
            if (!string.IsNullOrEmpty(context.ClientSecret))
            {
                var validClient = ValidateClient(context.ClientId, context.ClientSecret);
                if (validClient)
                {
                    context.Validate();
                }
            }

            return Task.CompletedTask;
        };

        //handler for the Token Requess which validate the grant type and the passed in auth data
        public static Func<HandleTokenRequestContext, Task> HandleTokenRequest = (context) =>
        {
            // Only handle grant_type=password token requests and client-Credentials requests
            // then let OpenID Connect server handle the other grant types.
            if (context.Request.IsClientCredentialsGrantType())
            {
                var identity = new ClaimsIdentity(context.Scheme.Name,
                  OpenIdConnectConstants.Claims.Name,
                  OpenIdConnectConstants.Claims.Role);

                //client credentials cals take an optional user assertion in an attempt
                //to avoid the 'confised deputy' issue on downstream api calls
                UserAssertion user = null;
                try
                {
                    var userAssertion = context.Request.GetParameter("user_assertion");
                    if (userAssertion.HasValue)
                    {
                        user = JsonConvert.DeserializeObject<UserAssertion>(userAssertion.Value.ToString());
                    }
                }
                catch
                {   //unable to get user info so set user to null and continue with the grant
                    user = null;
                }

                //can we get userID for the original user if passed via a user-assertion
                UserDto userDto = null;
                if (user != null) { userDto = KilohAuthProvider.GetUserById(user.UserId); }

                if (userDto != null)
                {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, user.UserId.ToString());
                    AddClaims(ref identity, user.UserId, context.Request.ClientId);//Infrastructure.Internal.JwtSecurity.ClientId);
                }
                else
                {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, context.Request.ClientId);//Infrastructure.Internal.JwtSecurity.ClientId);
                }

                var ticket = new AuthenticationTicket(
                     new ClaimsPrincipal(identity),
                     new AuthenticationProperties(),
                     context.Scheme.Name);

                //default client credentials tokens to a very short lifetime
                //they are only being used for 1 time downstream api requests
                ticket.SetAccessTokenLifetime(TimeSpan.FromMinutes(1));

                context.Validate(ticket);

                return Task.CompletedTask;

            }

            //handle condition for password grant requests
            if (context.Request.IsPasswordGrantType())
            {
                var validateResult = KilohAuthProvider.ValidateUser(context.Request.Username, context.Request.Password);
                if (!validateResult.Validated)
                {
                    var message = "Invalid user credentials";
                    context.Reject(
                       error: OpenIdConnectConstants.Errors.InvalidGrant,
                       description: message);


                    return Task.CompletedTask;
                }

                var identity = new ClaimsIdentity(context.Scheme.Name,
                    OpenIdConnectConstants.Claims.Name,
                    OpenIdConnectConstants.Claims.Role);

                //// Add the mandatory subject/user identifier claim.
                //identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "[unique id]");
                identity.AddClaim(OpenIdConnectConstants.Claims.Subject, validateResult.UserId != 0 ? validateResult.UserId.ToString() : "not_known");

                //// By default, claims are not serialized in the access/identity tokens.
                //// Use the overload taking a "destinations" parameter to make sure
                //// your claims are correctly inserted in the appropriate tokens.
                //add custom claims to the Identity
                AddClaims(ref identity, validateResult.UserId, context.Request.ClientId);// Infrastructure.Internal.JwtSecurity.ClientId);

                var ticket = new AuthenticationTicket(
                     new ClaimsPrincipal(identity),
                     new AuthenticationProperties(),
                     context.Scheme.Name);

                // Call SetScopes with the list of scopes you want to grant
                // (specify offline_access to issue a refresh token).
                ticket.SetScopes(
                    OpenIdConnectConstants.Scopes.OfflineAccess);

                //access and refresh token lifetime is determined by the client app
                var client = GetApiClientByIdAndSecret(context.Request.ClientId, context.Request.ClientSecret);

                ticket.SetAccessTokenLifetime(TimeSpan.FromMinutes(client.TokenLifetimeMinutes));
                ticket.SetRefreshTokenLifetime(TimeSpan.FromMinutes(client.RefreshTokenLifetimeMinutes));

                context.Validate(ticket);
            }

            return Task.CompletedTask;
        };

        public static bool ValidateClient(string clientId, string clientSecret)
        {
            var apiClient = GetApiClientByIdAndSecret(clientId, clientSecret);
            return apiClient != null;
        }


        public static ValidateUserResponse ValidateUser(string useremail, string password)
        {
            var response = new ValidateUserResponse { Validated = false };

            //1 - Decode the username (which is user email)
            //and the password
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            var decodedUserEmail = encoding.GetString(Convert.FromBase64String(useremail));
            var decodedPassword = encoding.GetString(Convert.FromBase64String(password));

            //2 - get the user by username (email address) only
            var emailQueryObject = new GetUserByEmailQuery(decodedUserEmail);
            var emailQueryHandler = new GetUserByEmailQueryHandler();
            var byEmailOnlyUser = emailQueryHandler.Handle(emailQueryObject).Result;
            if(byEmailOnlyUser == null)
            {
                return response;
            }
 
            //get salt associated with this user account
            var saltBytes = Convert.FromBase64String(byEmailOnlyUser.Salt);
            
            //append salt to password
            var passwordAndSalt = decodedPassword + Convert.ToBase64String(saltBytes);
            
            //hash the password using the salt
            var pbkdf2 = new Rfc2898DeriveBytes(passwordAndSalt, saltBytes, 10000);
            byte[] hashPassword = pbkdf2.GetBytes(32);

            //we check the hashed user given password against the hashedPassword stored for the user
            var hashedPasswordString = Convert.ToBase64String(hashPassword);
            var dbPassword = byEmailOnlyUser.PasswordHash;
            if (string.Compare(dbPassword, hashedPasswordString) != 0)
            {
                return response;
            }

            if (byEmailOnlyUser != null)
            {
                response.UserId = byEmailOnlyUser.UserId;
                response.Validated = true;
            }

            return response;

        }


        public static void AddClaims(ref ClaimsIdentity identity, int userId, string clientId)
        {

            UserDto user = GetUserById(userId);

            if (user != null)
            {
                //add the client_id to the claims
                identity.AddClaim(ClientIdClaimType, clientId, OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(ClaimTypes.Name, user.UserEmail, OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(UserEmailClaimType, user.UserEmail, OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(UserIDClaimType, user.UserId.ToString(), OpenIdConnectConstants.Destinations.AccessToken);

                //add user role(s) to the claims
                foreach (var userRole in user.UserRoles)
                {         
                    //serialize the role and add it to claims
                    var serializedRole = Newtonsoft.Json.JsonConvert.SerializeObject(userRole.Role);
                    identity.AddClaim(RoleClaimType, serializedRole, OpenIdConnectConstants.Destinations.AccessToken);
                }
            }

        }

        public static UserDto GetUserById(int userId)
        {
            var queryObject = new GetUserByIdQuery(userId);
            var handler = new GetUserByIdQueryHandler();
            UserDto user = handler.Handle(queryObject).Result;
            return user;
        }

        public static UserDto GetUserByEmail(string userEmail)
        {
            var queryObject = new GetUserByEmailQuery(userEmail);
            var handler = new GetUserByEmailQueryHandler();
            UserDto user = handler.Handle(queryObject).Result;
            return user;
        }

        public static ApiClientDto GetApiClientByIdAndSecret(string clientId, string clientSecret)
        {
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            var decodedId = encoding.GetString(Convert.FromBase64String(clientId));
            var decodedSecret = encoding.GetString(Convert.FromBase64String(clientSecret));

            var queryObject = new GetApiClientByIdQuery(decodedId, decodedSecret);
            var handler = new GetApiClientByIdQueryHandler();
            ApiClientDto client = handler.Handle(queryObject).Result;
            return client;
        }


    }
}
