using AspNetCoreRateLimit;
using Interfaces;
using JwtServer.AuthProviders;
using JwtServer.Infrastructure.Internal;
using JwtServer.Infrastructure.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SD.LLBLGen.Pro.DQE.PostgreSql;
using SD.LLBLGen.Pro.ORMSupportClasses;
using Swashbuckle.AspNetCore.Swagger;
using System;
using System.Collections.Generic;
using System.Linq;

namespace JwtServer
{
    /// <summary>
    /// Represents the startup process for the application.
    /// </summary>
    public class Startup
    {

        private string _host;
        private string _port;

        /// <summary>
        /// Initializes a new instance of the <see cref="Startup"/> class.
        /// </summary>
        /// <param name="env">The current hosting environment.</param>
        public Startup(IHostingEnvironment env)
        {

            var builder = new ConfigurationBuilder()
               .SetBasePath(env.ContentRootPath)
               .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
               .AddJsonFile($"secrets/appsettings.{env.EnvironmentName}.secrets.json", optional: true)
               .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
               .AddEnvironmentVariables();

            Configuration = builder.Build();

            ConfigureRuntimeDataContext();

        }

        /// <summary>
        /// sets up the RuntimeDatabaseContext for LLBLGen ORM
        /// </summary>
        public void ConfigureRuntimeDataContext()
        {
            //set up the PostgreSQL connection for LLBLGen ORM
            var connectionString = Configuration.GetConnectionString("JwtSecurityConn");

            RuntimeConfiguration.AddConnectionString("JwtSecurityConn",
               connectionString);
            
            RuntimeConfiguration.ConfigureDQE<PostgreSqlDQEConfiguration>(
                                            c => c.AddDbProviderFactory(typeof(Npgsql.NpgsqlFactory)));
                                                   
        }


        /// <summary>
        /// Gets the current configuration.
        /// </summary>
        /// <value>The current application configuration.</value>
        public IConfigurationRoot Configuration { get; }
        
        /// <summary>
        /// Configures services for the application.
        /// </summary>
        /// <param name="services">The collection of services to configure the application with.</param>
        public void ConfigureServices(IServiceCollection services)
        {

            // needed to load configuration from appsettings.json
            services.AddOptions();

            // needed to store rate limit counters and ip rules
            services.AddMemoryCache();

            //load general configuration from appsettings.json
            services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));

            //load ip rules from appsettings.json
            services.Configure<IpRateLimitPolicies>(Configuration.GetSection("IpRateLimitPolicies"));

            // inject counter and rules stores
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();

            //set up the HttpContextAccessor so our custom 'GetContextUser' can access user info for entity auto-auditing
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            //SET Up OpenIdConnectServer
            Infrastructure.Internal.JwtSecurity.JwtKey = Configuration["Jwt:Key"];
            Infrastructure.Internal.JwtSecurity.Issuer = Configuration["Jwt:Issuer"];
            Infrastructure.Internal.JwtSecurity.Audience = Configuration["Jwt:Audience"];

            services.AddAuthentication().AddOpenIdConnectServer(options =>
            {
                options.TokenEndpointPath = new PathString("/jwttoken");
                //options.AuthorizationEndpointPath = new PathString("/OAuth/Authorize");
                options.AuthorizationCodeLifetime = TimeSpan.FromMinutes(5);
                options.AccessTokenFormat = new CustomJwtFormat();
                options.AccessTokenLifetime = TimeSpan.FromMinutes(60);
                options.RefreshTokenLifetime = TimeSpan.FromMinutes(600);
                options.AllowInsecureHttp = true;
                options.ClaimsIssuer = Configuration["Jwt:Issuer"];
                // Implement OnHandleValidateRequest.
                options.Provider.OnValidateTokenRequest = (context) => KilohAuthProvider.ValidateTokenRequest(context);
                // Implement OnHandleTokenRequest
                options.Provider.OnHandleTokenRequest = (context) => KilohAuthProvider.HandleTokenRequest(context);
            }
            );

            //load mvc framework
            services.AddMvc();

            // add the versioned api explorer, which also adds IApiVersionDescriptionProvider service
            // note: the specified format code will format the version as "'v'major[.minor][-status]"
            services.AddMvcCore().AddVersionedApiExplorer(
                options =>
                {
                    options.GroupNameFormat = "'v'VVV";

                    // note: this option is only necessary when versioning by url segment. the SubstitutionFormat
                    // can also be used to control the format of the API version in route templates
                    options.SubstituteApiVersionInUrl = true;
                });


            services.AddApiVersioning(options => options.ReportApiVersions = true);
            services.AddSwaggerGen(
                options =>
                {
                    // resolve the IApiVersionDescriptionProvider service
                    // note: that we have to build a temporary service provider here because one has not been created yet
                    var provider = services.BuildServiceProvider().GetRequiredService<IApiVersionDescriptionProvider>();

                    // add a swagger document for each discovered API version
                    // note: you might choose to skip or document deprecated API versions differently
                    foreach (var description in provider.ApiVersionDescriptions)
                    {
                        options.SwaggerDoc(description.GroupName, CreateInfoForApiVersion(description));
                    }

                    options.AddSecurityDefinition("Bearer", new ApiKeyScheme { In = "header", Description = "Please enter JWT with Bearer into field", Name = "Authorization", Type = "apiKey" });
                    options.AddSecurityRequirement(new Dictionary<string, IEnumerable<string>> {
                        { "Bearer", Enumerable.Empty<string>() },
                    });

                    //note that password grants OAuth fow contains a bug in SwaggerUI which meakes them unusable at this point
                    //we therefore are not using the sign in functionality at the moment
                    //https://github.com/swagger-api/swagger-ui/issues/4192
                    //options.AddSecurityDefinition("oauth2", new OAuth2Scheme
                    //{
                    //     Type = "oauth2", Flow = "password", TokenUrl = "http://notimplemented"
                    //});

                    // add a custom operation filter which sets default values
                    options.OperationFilter<SwaggerDefaultValues>();

                    // integrate xml comments
                    //options.IncludeXmlComments(XmlCommentsFilePath);
                });

            services.AddScoped<IPropertyMappingService, PropertyMappingService>();
            
            //register the url helper
            //1st the url helper needs to know the context in which it is to run, so 
            //we need to 1st add the ActionContextAccessor as a Singleton
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
            //AddScoped creates an instance per request (i.e scoped to the request)
            services.AddScoped<IUrlHelper, UrlHelper>(implementationFactory =>
            {
                var actionContext = implementationFactory.GetService<IActionContextAccessor>().ActionContext;
                return new UrlHelper(actionContext);
            });

            services.AddScoped<ITypeHelperService, TypeHelperService>();
  
        }

        /// <summary>
        /// Configures the application using the provided builder, hosting environment, and logging factory.
        /// </summary>
        /// <param name="app">The current application builder.</param>
        /// <param name="env">The current hosting environment.</param>
        /// <param name="loggerFactory">The logging factory used for instrumentation.</param>
        /// <param name="provider">The API version descriptor provider used to enumerate defined API versions.</param>
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, IApiVersionDescriptionProvider provider, IApplicationLifetime applicationLifetime)
        {

            app.UseIpRateLimiting();

            app.UseAuthentication();

            app.UseMvc();

            app.UseSwagger();
            app.UseSwaggerUI(
                options =>
                {
                    //note that password grants OAuth fow contains a bug in SwaggerUI which meakes them unuable at this point
                    //we therefore are not using the sign in functionality at the moment
                    //https://github.com/swagger-api/swagger-ui/issues/4192
                    //options.OAuthClientId("");
                    //options.OAuthClientSecret("");

                    // build a swagger endpoint for each discovered API version
                    foreach (var description in provider.ApiVersionDescriptions)
                    {
                        options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
                    }

                });


            ConfigureHostAndPort(app);
 
        }

        static Info CreateInfoForApiVersion(ApiVersionDescription description)
        {
            var info = new Info()
            {
                Title = $"JwtServer {description.ApiVersion}",
                Version = description.ApiVersion.ToString(),
                Description = "JwtServer",
                Contact = new Contact() { Name = "Iain Kiloh", Email = "iainkiloh@gmail.com" },
                TermsOfService = "Private",
                License = new License() { Name = "None", Url = "https://kilohsoftware.com" }
            };

            if (description.IsDeprecated)
            {
                info.Description += " This API version has been deprecated.";
            }

            return info;
        }


        private void ConfigureHostAndPort(IApplicationBuilder app)
        {
            _host = Environment.MachineName;
            _port = "Unknown";

            var serverAddressFeature = (IServerAddressesFeature)app.ServerFeatures[typeof(Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature)];

            if (serverAddressFeature.Addresses.Count > 0)
            {
                var address = serverAddressFeature.Addresses.ElementAt(0);
                if (!string.IsNullOrEmpty(address))
                {
                    //_host = address;
                    var portIndex = address.LastIndexOf(":");
                    _port = address.Substring(portIndex + 1).TrimEnd('/');
                }
            }
        }



    }

}






////decode the clientID and clientSecret
//Encoding encoding = Encoding.GetEncoding("iso-8859-1");
//var decodedClientId = encoding.GetString(Convert.FromBase64String(context.ClientId));
//var decodedClientSecret = encoding.GetString(Convert.FromBase64String(context.ClientSecret));

//// Note: to mitigate brute force attacks, you SHOULD strongly consider applying
//// a key derivation function like PBKDF2 to slow down the secret validation process.
//// You SHOULD also consider using a time-constant comparer to prevent timing attacks.
//if (string.Equals(decodedClientId, Infrastructure.Internal.JwtSecurity.ClientId, StringComparison.Ordinal) &&
//    string.Equals(decodedClientSecret, Infrastructure.Internal.JwtSecurity.ClientSecret, StringComparison.Ordinal))
//{
//    // Note: if Validate() is not explicitly called,
//    // the request is automatically rejected.
//    context.Validate();
//}

////load mvc framework
//services.AddMvc(setup =>
//            {
//                setup.ReturnHttpNotAcceptable = true; //contect negotiation
//                setup.OutputFormatters.Add(new XmlDataContractSerializerOutputFormatter()); //add for xml formatting (default still json)
//                setup.OutputFormatters.Add(new XmlSerializerOutputFormatter()); //add for xml formatting (default still json)
//                setup.InputFormatters.Add(new XmlDataContractSerializerInputFormatter()); //add support for xml input in request body
//                //add standard ProducesResponseType Filters for typical 400 errors
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status400BadRequest));
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status401Unauthorized));
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status403Forbidden));
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status404NotFound));
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status406NotAcceptable));
//                setup.Filters.Add(new ProducesResponseTypeAttribute(StatusCodes.Status415UnsupportedMediaType));
//            }).AddJsonOptions(options =>
//            {
//    options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
//});
