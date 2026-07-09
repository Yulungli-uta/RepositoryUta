using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Graph;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;
using System.Threading.RateLimiting;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Hubs;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.EntraId;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd;
using WsSeguUta.AuthSystem.API.Infrastructure.Mapping;
using WsSeguUta.AuthSystem.API.Infrastructure.Validation;
using WsSeguUta.AuthSystem.API.Middleware;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services;
using WsSeguUta.AuthSystem.API.Services.Implementations;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// =========================================================
// Config: appsettings.json en ubicación personalizada
// =========================================================
builder.Host.ConfigureAppConfiguration((hostingContext, config) =>
{
    var env = hostingContext.HostingEnvironment;
    config.SetBasePath(Directory.GetCurrentDirectory());
    config.AddJsonFile("Configuration/appsettings.json", optional: false, reloadOnChange: true);
    config.AddJsonFile($"Configuration/appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true);
    if (env.IsDevelopment())
        config.AddUserSecrets<Program>(optional: true);
    config.AddEnvironmentVariables();
});

// DEBUG: Connection string
var connectionString = builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("Connection string 'Default' not found or is empty");
}

// =========================================================
// Serilog — configuración leída desde appsettings.json
// =========================================================
builder.Host.UseSerilog((context, config) =>
    config.ReadFrom.Configuration(context.Configuration));

// =========================================================
// DB
// =========================================================
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(connectionString,
        x => x.MigrationsAssembly(typeof(AuthDbContext).Assembly.FullName)));

// =========================================================
// DI / MVC
// =========================================================
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();
builder.Services.AddAutoMapper(typeof(MappingProfile));
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(opt =>
    {
        // Deshabilitar el filtro automático de ModelState inválido para poder
        // suprimir errores de campos generados internamente (ej: Email en provisioning).
        opt.SuppressModelStateInvalidFilter = true;
    })
    .AddJsonOptions(opt =>
    {
        opt.JsonSerializerOptions.RespectRequiredConstructorParameters = false;
    });
builder.Services.AddValidators();

// =========================================================
// CORS (desde appsettings.json)
// =========================================================
var cors = builder.Configuration.GetSection("Cors");
var corsName = cors["PolicyName"] ?? "Frontend";
var configOrigins = cors.GetSection("Origins").Get<string[]>() ?? Array.Empty<string>();

// Orígenes de desarrollo/pruebas, solo en entorno Development.
var devOrigins = builder.Environment.IsDevelopment()
    ? new[] { "http://localhost:5173", "http://localhost:3000", "http://localhost:5010" }
    : Array.Empty<string>();
var origins = configOrigins.Concat(devOrigins).Distinct().ToArray();

var allowCred = bool.TryParse(cors["AllowCredentials"], out var ac) && ac;
var allowedHeaders = cors.GetSection("AllowedHeaders").Get<string[]>();
var allowedMethods = cors.GetSection("AllowedMethods").Get<string[]>();

builder.Services.AddCors(opt =>
{
    opt.AddPolicy(corsName, policy =>
    {
        // WithOrigins + AllowCredentials es la combinación correcta para SignalR
        policy.WithOrigins(origins);

        if (allowedHeaders is { Length: > 0 })
            policy.WithHeaders(allowedHeaders);
        else
            policy.AllowAnyHeader();

        if (allowedMethods is { Length: > 0 })
            policy.WithMethods(allowedMethods);
        else
            policy.AllowAnyMethod();

        if (allowCred)
            policy.AllowCredentials();

        policy.SetPreflightMaxAge(TimeSpan.FromHours(12));
    });
});

// =========================================================
// Rate Limiting
// =========================================================
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "anon",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 6,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }
        ));
});

// =========================================================
// JWT (RS256) — clave pública/privada gestionada por RsaKeyProvider
// =========================================================
var rsaKeyProviderLogger = LoggerFactory.Create(b => b.AddConsole())
    .CreateLogger<WsSeguUta.AuthSystem.API.Security.RsaKeyProvider>();
var rsaKeyProvider = new WsSeguUta.AuthSystem.API.Security.RsaKeyProvider(
    builder.Configuration, builder.Environment, rsaKeyProviderLogger);
builder.Services.AddSingleton(rsaKeyProvider);

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
var jwtAud = builder.Configuration["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAud,
            IssuerSigningKey = rsaKeyProvider.PublicKey,
            ClockSkew = TimeSpan.FromMinutes(2)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();
});

// =========================================================
// Swagger
// =========================================================
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "WsSeguUta.AuthSystem.API", Version = "v1" });

    var jwtScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Bearer"
    };

    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtScheme, Array.Empty<string>() }
    });
});

// =========================================================
// Repos / Services
// =========================================================
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthRepository, AuthRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<IMenuRepository, MenuRepository>();
builder.Services.AddScoped<IUserPermissionRepository, UserPermissionRepository>();
builder.Services.AddScoped<IApplicationRepository, ApplicationRepository>();
builder.Services.AddScoped<IClientApplicationService, ClientApplicationService>();

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAzureAuthService, AzureAuthService>();
builder.Services.AddScoped<IMenuService, MenuService>();
builder.Services.AddScoped<IAppAuthService, AppAuthService>();
builder.Services.AddScoped<INotificationService, NotificationService>();
builder.Services.AddScoped<IWebSocketConnectionService, WebSocketConnectionService>();
builder.Services.AddScoped<IUserPermissionService, UserPermissionService>();
builder.Services.AddScoped<IUserRegistrationService, UserRegistrationService>();
builder.Services.AddScoped<IInstitutionalEmailGenerator, InstitutionalEmailGenerator>();
builder.Services.AddScoped<IEmployeeProvisioningService, EmployeeProvisioningService>();
builder.Services.AddScoped<IStudentProvisioningService, StudentProvisioningService>();
builder.Services.AddScoped<IMicrosoftLicenseService, MicrosoftLicenseService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ISessionManagementService, SessionManagementService>();

// =========================================================
// Azure Management Service
// =========================================================
builder.Services.AddScoped<IAzureAdRepository, AzureAdRepository>();
builder.Services.AddScoped<IAzureManagementService, AzureManagementService>();

// GraphServiceClient para Microsoft Graph API
builder.Services.AddSingleton<GraphServiceClient>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var tenantId = config["AzureAd:TenantId"];
    var clientId = config["AzureAd:ClientId"];
    var clientSecret = config["AzureAd:ClientSecret"];

    if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        throw new InvalidOperationException("Azure AD configuration is missing: AzureAd:TenantId, AzureAd:ClientId, AzureAd:ClientSecret");

    var credential = new Azure.Identity.ClientSecretCredential(tenantId, clientId, clientSecret,
        new Azure.Identity.ClientSecretCredentialOptions { AuthorityHost = Azure.Identity.AzureAuthorityHosts.AzurePublicCloud });

    return new GraphServiceClient(credential);
});

// IConfidentialClientApplication (MSAL) como Singleton para reutilizar token cache
builder.Services.AddSingleton<Microsoft.Identity.Client.IConfidentialClientApplication>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var tenantId = config["AzureAd:TenantId"]
        ?? throw new InvalidOperationException("AzureAd:TenantId no configurado.");
    var clientId = config["AzureAd:ClientId"]
        ?? throw new InvalidOperationException("AzureAd:ClientId no configurado.");
    var secret = config["AzureAd:ClientSecret"]
        ?? throw new InvalidOperationException("AzureAd:ClientSecret no configurado.");
    var redirect = config["AzureAd:RedirectUri"]
        ?? throw new InvalidOperationException("AzureAd:RedirectUri no configurado.");

    return Microsoft.Identity.Client.ConfidentialClientApplicationBuilder
        .Create(clientId)
        .WithAuthority($"https://login.microsoftonline.com/{tenantId}/v2.0")
        .WithClientSecret(secret)
        .WithRedirectUri(redirect)
        .Build();
});

// SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// CRUD genérico
builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped(typeof(ICrudService<,,>), typeof(CrudService<,,>));

// Servicios específicos que sobreescriben el CrudService genérico para agregar lógica de negocio
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto>, UserRoleService>();

builder.Services.AddSingleton<WsSeguUta.AuthSystem.API.Security.JwtTokenService>();

// =========================================================
// Multi-provider Identity
// =========================================================
builder.Services.Configure<LocalAdOptions>(builder.Configuration.GetSection(LocalAdOptions.Section));
builder.Services.Configure<ProvisioningOptions>(builder.Configuration.GetSection(ProvisioningOptions.Section));

builder.Services.AddScoped<IIdentityProvider, EntraIdIdentityProvider>();
builder.Services.AddScoped<IIdentityProvider, LocalAdIdentityProvider>();

builder.Services.AddScoped<IDirectoryService, EntraIdDirectoryService>();
builder.Services.AddScoped<IDirectoryService, LocalAdDirectoryService>();

builder.Services.AddScoped<IIdentityProviderResolver, IdentityProviderResolver>();

builder.Services.AddHealthChecks().AddDbContextCheck<AuthDbContext>();

// Si hay proxy/reverse proxy (Apache/Nginx), útil:
builder.Services.Configure<ForwardedHeadersOptions>(opts =>
{
    opts.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

// =========================================================
// Pipeline
// =========================================================
var app = builder.Build();

// Intercepta OPTIONS preflights ANTES de routing porque SignalR negotiate solo registra POST
// y UseCors() con RequireCors() no agrega headers cuando no hay endpoint match para OPTIONS.
app.Use(async (context, next) =>
{
    if (context.Request.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
    {
        var origin = context.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin) && origins.Contains(origin, StringComparer.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 204;
            context.Response.Headers["Access-Control-Allow-Origin"] = origin;
            context.Response.Headers["Access-Control-Allow-Credentials"] = "true";
            context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
            context.Response.Headers["Access-Control-Allow-Headers"] = "content-type, authorization, x-requested-with, x-signalr-user-agent";
            context.Response.Headers["Access-Control-Max-Age"] = "86400";
            context.Response.Headers["Vary"] = "Origin";
            return;
        }
    }
    await next();
});

app.UseSerilogRequestLogging();
app.UseForwardedHeaders();

// ✅ CRÍTICO: routing antes de CORS
app.UseRouting();

// ✅ CRÍTICO: CORS entre UseRouting y Auth/Endpoints
app.UseCors(corsName);

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<ErrorHandlerMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ✅ Endpoints (una sola vez)
app.MapControllers().RequireCors(corsName);
app.MapHealthChecks("/healthz");

// ✅ Hub con CORS aplicado
app.MapHub<NotificationHub>("/notificationHub").RequireCors(corsName);

app.Run();
