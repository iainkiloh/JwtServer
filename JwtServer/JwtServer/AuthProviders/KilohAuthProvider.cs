using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using JwtSecurityContracts.DtoClasses;
using JwtServer.Infrastructure;
using QueryObjects;
using QueryObjects.Queries;
using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtServer.AuthProviders
{
    public static class KilohAuthProvider
    {

        //Custom Claim Types
        public const string UserIDClaimType = "KilohApp/UserId";
        public const string RoleClaimType = "KilohApp/SystemRole";
        public const string ClientIdClaimType = "KilohApp/ClientId";
        public const string UserEmailClaimType = "KilohApp/UserEmail";

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
