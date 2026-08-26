FROM mcr.microsoft.com/dotnet/sdk:10.0
WORKDIR /app

COPY shady-blob-store.cs ./
RUN dotnet restore shady-blob-store.cs

EXPOSE 8080
ENTRYPOINT ["dotnet", "run", "--file", "shady-blob-store.cs", "--no-restore", "--no-launch-profile"]
