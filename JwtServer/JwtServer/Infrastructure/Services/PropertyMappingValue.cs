using Interfaces;
using System.Collections.Generic;

namespace JwtServer.Infrastructure.Services
{
    public class PropertyMappingValue : IPropertyMappingValue
    {

        public IEnumerable<string> DestinationProperties { get; private set; }

        public bool Revert { get; private set; }

        public PropertyMappingValue(IEnumerable<string> destinationProperties, bool revert = false)
        {
            DestinationProperties = destinationProperties;
            Revert = revert;
        }

    }
}
