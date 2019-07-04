using Interfaces;
using System;
using System.Reflection;

namespace JwtServer.Infrastructure.Services
{
    public class TypeHelperService : ITypeHelperService
    {
        public void CheckTypeProperties<T>(string fields)
        {
            if(string.IsNullOrEmpty(fields)) { return; }

            //split fields comma separated list
            var fieldsAfterSplit = fields.Split(',');

            foreach(var field in fieldsAfterSplit)
            {
                var propertyName = field.Trim();

                var propertyInfo = typeof(T).GetProperty(
                    propertyName, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance);

                if(propertyInfo == null)
                {
                    throw new ArgumentNullException($"property {propertyName} not found for type {typeof(T)}");
                }
            }
        }
    }
}
