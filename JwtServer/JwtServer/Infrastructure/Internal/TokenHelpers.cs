using Microsoft.AspNetCore.Authentication;
using System;
using System.IdentityModel.Tokens.Jwt;


namespace JwtServer.Infrastructure.Internal
{
    public static class JwtSecurity
    {
        public static string JwtKey { get; set; }
        public static string Issuer { get; set; }
        public static string Audience { get; set; }
        
        public static Microsoft.IdentityModel.Tokens.SymmetricSecurityKey Create()
        {
            var symmetricKey = Convert.FromBase64String(JwtKey);
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(symmetricKey);
            return securityKey;
        }

    }

    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {

        public string Protect(AuthenticationTicket data, string purpose)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            var securityKey = JwtSecurity.Create();
            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = JwtSecurity.Issuer,
                Audience = JwtSecurity.Audience,
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                                               securityKey,
                                               Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256),

                Expires = data.Properties.ExpiresUtc.Value.UtcDateTime,
                NotBefore = DateTime.UtcNow,

                Subject = (System.Security.Claims.ClaimsIdentity)data.Principal.Identity
            });

            return handler.WriteToken(securityToken);
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            var securityKey = JwtSecurity.Create();
            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = JwtSecurity.Issuer,
                Audience = JwtSecurity.Audience,
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                                               securityKey,
                                               Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256),

                Expires = data.Properties.ExpiresUtc.Value.UtcDateTime,
                NotBefore = DateTime.UtcNow,
               
                Subject = (System.Security.Claims.ClaimsIdentity)data.Principal.Identity
            });

            return handler.WriteToken(securityToken);
        }

        public AuthenticationTicket Unprotect(string protectedText, string purpose)
        {
            throw new NotImplementedException();
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}
