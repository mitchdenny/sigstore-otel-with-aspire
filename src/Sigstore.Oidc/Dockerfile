FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Sigstore.Oidc.csproj ./
RUN dotnet restore Sigstore.Oidc.csproj

COPY . ./
RUN dotnet publish Sigstore.Oidc.csproj \
    --configuration Release \
    --no-restore \
    --output /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

COPY --from=build /out ./

EXPOSE 8443
ENTRYPOINT ["dotnet", "Sigstore.Oidc.dll"]
