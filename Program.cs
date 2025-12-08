using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;
using System.Threading.RateLimiting;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Infrastructure.Validation;
using WsSeguUta.AuthSystem.API.Infrastructure.Mapping;
using WsSeguUta.AuthSystem.API.Middleware;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Services.Implementations;
using WsSeguUta.AuthSystem.API.Services;
using WsSeguUta.AuthSystem.API.Data.Repositories;
//using HealthChecks.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Configura la ubicación personalizada para appsettings.json
builder.Host.ConfigureAppConfiguration((hostingContext, config) =>
{
    config.SetBasePath(Directory.GetCurrentDirectory());
    config.AddJsonFile("Configuration/appsettings.json", optional: false, reloadOnChange: true);
    config.AddEnvironmentVariables();
});

// DEBUGGING: Verificar configuración
Console.WriteLine($"Current Environment: {builder.Environment.EnvironmentName}");
var connectionString = builder.Configuration.GetConnectionString("Default");
Console.WriteLine($"Connection String Found: {!string.IsNullOrEmpty(connectionString)}");
Console.WriteLine($"Connection String Length: {connectionString?.Length ?? 0}");

if (string.IsNullOrEmpty(connectionString))
{
    Console.WriteLine("ERROR: Connection string is null or empty!");
    Console.WriteLine("Available connection strings:");
    var connStrings = builder.Configuration.GetSection("ConnectionStrings");
    foreach (var item in connStrings.GetChildren())
    {
        Console.WriteLine($"  {item.Key}: {item.Value}");
    }
    throw new InvalidOperationException("Connection string 'Default' not found or is empty");
}

// Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();
builder.Host.UseSerilog();


// DB
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"),
        x => x.MigrationsAssembly(typeof(AuthDbContext).Assembly.FullName)));

// DI
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();
builder.Services.AddAutoMapper(typeof(MappingProfile));
builder.Services.AddControllers();
builder.Services.AddValidators();

// CORS
builder.Services.AddCors(opts => {
    opts.AddPolicy("default", p =>
        p.WithOrigins("http://localhost:5173","http://localhost:3000")
         .AllowAnyHeader().AllowAnyMethod().AllowCredentials());
});

// Rate-limiting
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "anon",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 6, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }
        ));
});

// JWT
var jwtKey    = builder.Configuration["Jwt:Key"]      ?? "cambia-esta-clave-larga-segura";
var jwtIssuer = builder.Configuration["Jwt:Issuer"]   ?? "WsSeguUta.AuthSystem.API";
var jwtAud    = builder.Configuration["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

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
        .RequireAuthenticatedUser().Build();
});

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "WsSeguUta.AuthSystem.API", Version = "v1" });
    var jwtScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization", Type = SecuritySchemeType.Http, Scheme = "bearer",
        BearerFormat = "JWT", In = ParameterLocation.Header, Description = "JWT Bearer"
    };
    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement { { jwtScheme, Array.Empty<string>() } });
});

// Repos / Services
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

// SignalR para notificaciones en tiempo real
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// CRUD genÃ©rico (todas las tablas)
builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped(typeof(ICrudService<,,>), typeof(CrudService<,,>));

builder.Services.AddSingleton<WsSeguUta.AuthSystem.API.Security.JwtTokenService>();
builder.Services.AddHealthChecks().AddDbContextCheck<AuthDbContext>();

var app = builder.Build();
app.UseSerilogRequestLogging();
app.UseCors("default");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<ErrorHandlerMiddleware>();
app.UseSwagger();
app.UseSwaggerUI();
app.MapControllers();
app.MapHealthChecks("/healthz");
app.MapHub<WsSeguUta.AuthSystem.API.Hubs.NotificationHub>("/notificationHub");
app.Run();
