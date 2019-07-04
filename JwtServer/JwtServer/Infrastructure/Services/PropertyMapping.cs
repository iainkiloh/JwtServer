using Interfaces;
using System.Collections.Generic;

namespace JwtServer.Infrastructure.Services
{
    public class PropertyMapping<TSource, TDestination> : IPropertyMapping
    {

        public Dictionary<string, IPropertyMappingValue> _mappingDictionary { get; private set; }

        public PropertyMapping(Dictionary<string, IPropertyMappingValue> mappingDictionary)
        {
            _mappingDictionary = mappingDictionary;
        }

    }
}
