using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace JwtServer.Infrastructure.Internal
{
    public static class IEnumerableExtensions
    {

        public static IEnumerable<ExpandoObject> ShapeData<TSource>(
            this IEnumerable<TSource> source, string fields)
        {
            if (source == null) { throw new ArgumentNullException("source"); }
            if (string.IsNullOrEmpty(fields)) { throw new ArgumentNullException("fields"); }

            var expandoObjectList = new List<ExpandoObject>();

            //get list of properties on the source type
            var propertyInfoList = new List<PropertyInfo>();
            //split comma separated fields
            var fieldsAfterSplit = fields.Split(',');
            foreach (var field in fieldsAfterSplit)
            {
                var propertyName = field.Trim();
                var propertyInfo = typeof(TSource).GetProperty(
                    propertyName, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance);

                if (propertyInfo == null) { throw new Exception($"Property {propertyName} was not found on type {typeof(TSource)}"); }
                propertyInfoList.Add(propertyInfo);

            }

            foreach(TSource item in source)
            {
                var dataShapedItem = new ExpandoObject();
                foreach(var prop in propertyInfoList)
                {
                     var propValue = prop.GetValue(item);
                     ((IDictionary<string,object>)dataShapedItem).Add(prop.Name, propValue);
                }

                expandoObjectList.Add(dataShapedItem);

             }

            return expandoObjectList;

        }

    }
}
