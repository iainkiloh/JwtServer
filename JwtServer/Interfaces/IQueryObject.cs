using System.Threading.Tasks;
namespace Interfaces
{
    public interface IQueryObject<out TResponse> : IBaseQueryObject { }

    /// <summary>
    /// Allows for generic type constraints of objects implementing IQueryObject{TResponse}
    /// </summary>
    public interface IBaseQueryObject { }


    public interface IQueryHandler<in TQueryObject, TResponse>
    where TQueryObject : IQueryObject<TResponse>
    {
        Task<TResponse> Handle(TQueryObject queryObject);
    }

}

