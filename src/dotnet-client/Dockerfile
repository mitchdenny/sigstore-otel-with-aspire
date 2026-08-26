FROM mcr.microsoft.com/dotnet/sdk:10.0
WORKDIR /app

COPY dotnet-client.cs ./
RUN dotnet restore dotnet-client.cs

EXPOSE 8080
ENTRYPOINT ["dotnet", "run", "--file", "dotnet-client.cs", "--no-restore", "--no-launch-profile"]
