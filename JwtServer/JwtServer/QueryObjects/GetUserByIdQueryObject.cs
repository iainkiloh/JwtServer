using Interfaces;
using JwtSecurity.DatabaseSpecific;
using JwtSecurityContracts.DtoClasses;
using JwtSecurityContracts.Persistence;
using SD.LLBLGen.Pro.LinqSupportClasses;
using System.Linq;
using System.Threading.Tasks;

namespace QueryObjects
{
    public class GetUserByIdQuery : IQueryObject<UserDto>
    {
        public GetUserByIdQuery(int userId)
        {
            UserId = userId;
        }

        public int UserId { get; }
    }
}


namespace QueryObjects.Queries
{
    public class GetUserByIdQueryHandler : IQueryHandler<GetUserByIdQuery, UserDto>
    {
        public GetUserByIdQueryHandler() { }

        public async Task<UserDto> Handle(GetUserByIdQuery queryObject)
        {
            
            var md = new JwtSecurity.Linq.LinqMetaData();

            var query = md.User
                .Where(x => x.UserId == queryObject.UserId) 
                .ProjectToUserDto();

            using (var adapter = new DataAccessAdapter())
            {
                ((LLBLGenProProvider2)query.Provider).AdapterToUse = adapter;
                return await query.FirstOrDefaultAsync();
            }

        }
    }

}



