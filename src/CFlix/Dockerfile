FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY CFlix/CFlix.csproj CFlix/CFlix.csproj
COPY CFlix.ActiveDirectory.NETStandard/CFlix.ActiveDirectory.NETStandard.csproj CFlix.ActiveDirectory.NETStandard/CFlix.ActiveDirectory.NETStandard.csproj
COPY CFlix.sln ./
RUN dotnet restore CFlix.sln

COPY . ./
RUN dotnet publish CFlix/CFlix.csproj -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
EXPOSE 80
COPY --from=build /out ./
ENTRYPOINT ["dotnet", "CFlix.dll"]