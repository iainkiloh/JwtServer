namespace JwtServer.Infrastructure.Internal
{

    public class UserAssertion
    {
        public int UserId { get; set; }
        public string UserEmail { get; set; }
       
        public UserAssertionRole[] Roles { get; set; }
    }

    public class UserAssertionRole
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
    }

}
