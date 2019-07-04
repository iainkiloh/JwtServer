using Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JwtServer.Infrastructure.Services
{

    public class PropertyMappingService : IPropertyMappingService
    {

        private IList<IPropertyMapping> propertyMappings = new List<IPropertyMapping>();

        public PropertyMappingService()
        {
           
        }

        public Dictionary<string, IPropertyMappingValue> GetPropertyMapping<TSource,TDestination>()
        {
            //get matching mapping
            var match = propertyMappings.OfType<PropertyMapping<TSource, TDestination>>();
            if(match.Count() == 1)
            {
                return match.First()._mappingDictionary;
            }

            throw new Exception($"Cannot find exact property mapping instance for <{typeof(TSource)}>, to <{typeof(TDestination)}>");
        }

        public bool ValidMappingExistsFor<TSource, TDestination>(string fields)
        {
            var propertyMapping = GetPropertyMapping<TSource, TDestination>();

            if (string.IsNullOrEmpty(fields)) { return true; }

            var fieldsAfterSplit = fields.Split(',');

            foreach (var field in fieldsAfterSplit)
            {
                var trimmedField = field.Trim();

                var indexOfFirstSpace = trimmedField.IndexOf(" ");
                var propertyName = indexOfFirstSpace == -1 ?
                    trimmedField : trimmedField.Remove(indexOfFirstSpace);

                //find the matching property
                if(!propertyMapping.ContainsKey(propertyName))
                {
                    throw new ArgumentNullException($"no property mapping found for propery name: {propertyName}");
                }

            }

            return true;

        }


    }
}
