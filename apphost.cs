#:sdk Aspire.AppHost.Sdk@13.5.2
#:property AspireUseCliBundle=true

var builder = DistributedApplication.CreateBuilder(args);

// The aspireify skill will wire up your projects here.

builder.Build().Run();