# IdentityEF
Dot Net Core 6 Web API with Identity providing Authentication &amp; Authorization using JWT.

# Use dotnet CLI to migrate EF

- Check if dotnet CLI is installed

  dotnet --version
- install dotnet-ef

  dotnet tool install --global dotnet-ef --version 6.*
- run migration

  dotnet ef migrations add InitialCreate

https://stackoverflow.com/questions/57066856/command-dotnet-ef-not-found
