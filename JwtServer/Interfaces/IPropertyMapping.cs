using System.Collections.Generic;

namespace Interfaces
{
    public interface IPropertyMapping
    {
    }

    public interface IPropertyMappingValue
    {
        IEnumerable<string> DestinationProperties { get; }
        bool Revert { get; }

    }

    public interface IPropertyMappingService
    {
        Dictionary<string, IPropertyMappingValue> GetPropertyMapping<TSource, TDestination>();

        bool ValidMappingExistsFor<TSource, TDestination>(string fields);

    }



}
