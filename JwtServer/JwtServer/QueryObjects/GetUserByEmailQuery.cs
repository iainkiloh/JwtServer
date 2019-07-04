using Interfaces;
using JwtSecurity.DatabaseSpecific;
using JwtSecurityContracts.DtoClasses;
using JwtSecurityContracts.Persistence;
using SD.LLBLGen.Pro.LinqSupportClasses;
using System.Linq;
using System.Threading.Tasks;

namespace QueryObjects
{
    public class GetUserByEmailQuery : IQueryObject<UserDto>
    {
        public GetUserByEmailQuery(string userEmail)
        {
            UserEmail = userEmail;
        }

        public string UserEmail { get; }
    }
}


namespace QueryObjects.Queries
{
    public class GetUserByEmailQueryHandler : IQueryHandler<GetUserByEmailQuery, UserDto>
    {
        public GetUserByEmailQueryHandler() { }

        public async Task<UserDto> Handle(GetUserByEmailQuery queryObject)
        {

            var md = new JwtSecurity.Linq.LinqMetaData();

            var query = md.User
                .Where(x => x.UserEmail == queryObject.UserEmail)
                .ProjectToUserDto();

            using (var adapter = new DataAccessAdapter())
            {
                ((LLBLGenProProvider2)query.Provider).AdapterToUse = adapter;
                return await query.FirstOrDefaultAsync();
            }

        }
    }

}



