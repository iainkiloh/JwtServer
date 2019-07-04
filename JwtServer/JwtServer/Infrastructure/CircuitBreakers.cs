using Polly;
using System;
using System.Data.SqlClient;

namespace JwtServer.Infrastructure
{

    public static class CircuitBreakers
    {

        private static Policy _breaker = null;

        /// <summary>
        /// Creates a circuit breaker which stops further calls attempting to access SQL if it is continually timing out
        /// On 3 successive SQL timeouts, we open the cicruit breaker for 1 minute
        /// </summary>
        public static Policy Breaker
        {
            get
            {
                if (_breaker == null)
                {
                    _breaker = Policy
                  .Handle<SqlException>(x => x.Number == -2) //-2 is sql timeout error code
                      .CircuitBreakerAsync(3, TimeSpan.FromMinutes(1)); //set the Cricuit to close to stop incoming calls
                }
                return _breaker;
            }
        }

    }

}