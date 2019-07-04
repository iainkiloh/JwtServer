using Interfaces;
using JwtSecurity.DatabaseSpecific;
using JwtSecurityContracts.DtoClasses;
using JwtSecurityContracts.Persistence;
using SD.LLBLGen.Pro.LinqSupportClasses;
using System.Linq;
using System.Threading.Tasks;

namespace QueryObjects
{
    public class GetApiClientByIdQuery : IQueryObject<ApiClientDto>
    {
        public GetApiClientByIdQuery(string clientId, string clientSecret)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        public string ClientId { get; }
        public string ClientSecret { get; }
    }
}


namespace QueryObjects.Queries
{
    public class GetApiClientByIdQueryHandler : IQueryHandler<GetApiClientByIdQuery, ApiClientDto>
    {
        public GetApiClientByIdQueryHandler() { }

        public async Task<ApiClientDto> Handle(GetApiClientByIdQuery queryObject)
        {

            var md = new JwtSecurity.Linq.LinqMetaData();

            var query = md.ApiClient
                .Where(x => x.ClientId == queryObject.ClientId && x.ClientSecret == queryObject.ClientSecret)
                .ProjectToApiClientDto();

            using (var adapter = new DataAccessAdapter())
            {
                ((LLBLGenProProvider2)query.Provider).AdapterToUse = adapter;
                return await query.FirstOrDefaultAsync();
            }

        }
    }

}



