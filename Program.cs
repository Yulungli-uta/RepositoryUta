using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.Graph;
using Azure.Identity;
using Serilog;
using Serilog.Events;
using System.Text;
using System.Threading.RateLimiting;

using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Infrastructure.Mapping;
using WsSeguUta.AuthSystem.API.Infrastructure.Validation;
using WsSeguUta.AuthSystem.API.Middleware;
using WsSeguUta.AuthSystem.API.Services;
using WsSeguUta.AuthSystem.API.Services.Implementations;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Hubs;

var builder = WebApplication.CreateBuilder(args);

// =========================================================
// Config: appsettings.json en ubicación personalizada
// =========================================================
builder.Host.ConfigureAppConfiguration((hostingContext, config) =>
{
    config.SetBasePath(Directory.GetCurrentDirectory());
    config.AddJsonFile("Configuration/appsettings.json", optional: false, reloadOnChange: true);
    config.AddEnvironmentVariables();
});

// DEBUG: Connection string
var connectionString = builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("Connection string 'Default' not found or is empty");
}

// =========================================================
// Serilog
// =========================================================
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

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
builder.Services.AddControllers();
builder.Services.AddValidators();

// =========================================================
// CORS (desde appsettings.json)
// =========================================================
var cors = builder.Configuration.GetSection("Cors");
var corsName = cors["PolicyName"] ?? "Frontend";
var origins = cors.GetSection("Origins").Get<string[]>() ?? Array.Empty<string>();
var allowCred = bool.TryParse(cors["AllowCredentials"], out var ac) && ac;

builder.Services.AddCors(opt =>
{
    opt.AddPolicy(corsName, policy =>
    {
        if (origins.Length > 0)
        {
            policy.WithOrigins(origins);
        }
        else
        {
            // Evita dejar esto abierto en prod si AllowCredentials = true
            policy.AllowAnyOrigin();
        }

        // Recomendado para evitar errores por headers (SignalR + navegadores)
        policy.AllowAnyHeader();
        policy.AllowAnyMethod();

        if (allowCred)
            policy.AllowCredentials();

        // Opcional: cache de preflight (reduce OPTIONS)
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
// JWT
// =========================================================
var jwtKey = builder.Configuration["Jwt:Key"] ?? "cambia-esta-clave-larga-segura";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
var jwtAud = builder.Configuration["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAud,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
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

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAzureAuthService, AzureAuthService>();
builder.Services.AddScoped<IMenuService, MenuService>();
builder.Services.AddScoped<IAppAuthService, AppAuthService>();
builder.Services.AddScoped<INotificationService, NotificationService>();
builder.Services.AddScoped<IWebSocketConnectionService, WebSocketConnectionService>();
builder.Services.AddScoped<IUserPermissionService, UserPermissionService>();

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
    {
        throw new InvalidOperationException("Azure AD configuration is missing. Please configure AzureAd:TenantId, AzureAd:ClientId, and AzureAd:ClientSecret in appsettings.json");
    }
    
    var options = new Azure.Identity.ClientSecretCredentialOptions
    {
        AuthorityHost = Azure.Identity.AzureAuthorityHosts.AzurePublicCloud
    };
    
    var credential = new Azure.Identity.ClientSecretCredential(tenantId, clientId, clientSecret, options);
    return new GraphServiceClient(credential);
});

// SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// CRUD genérico
builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped(typeof(ICrudService<,,>), typeof(CrudService<,,>));

builder.Services.AddSingleton<WsSeguUta.AuthSystem.API.Security.JwtTokenService>();

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

app.UseSwagger();
app.UseSwaggerUI();

// ✅ Endpoints (una sola vez)
app.MapControllers().RequireCors(corsName);
app.MapHealthChecks("/healthz");

// ✅ Hub con CORS aplicado
app.MapHub<NotificationHub>("/notificationHub").RequireCors(corsName);

app.Run();
