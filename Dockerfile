FROM mcr.microsoft.com/dotnet/core/aspnet:2.2 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/core/sdk:2.2 AS build
WORKDIR /src
COPY *.sln ./
COPY JwtServer/JwtServer/JwtServer.csproj JwtServer/JwtServer/
COPY JwtServer/Interfaces/Interfaces.csproj JwtServer/Interfaces/
COPY JwtServer/Model/JwtSecurityContracts/JwtSecurityContracts.csproj JwtServer/Model/JwtSecurityContracts/
COPY JwtServer/Model/DatabaseGeneric/JwtSecurity.csproj JwtServer/Model/DatabaseGeneric/
COPY JwtServer/Model/JwtSecurityContracts.Persistence/JwtSecurityContracts.Persistence.csproj JwtServer/Model/JwtSecurityContracts.Persistence/
COPY JwtServer/Model/DatabaseSpecific/JwtSecurityDBSpecific.csproj JwtServer/Model/DatabaseSpecific/
RUN dotnet restore
COPY . .
WORKDIR /src/JwtServer/JwtServer
RUN dotnet build -c Release -o /app

FROM build AS publish
RUN dotnet publish -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "JwtServer.dll"]
