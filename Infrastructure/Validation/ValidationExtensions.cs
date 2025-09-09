using Microsoft.Extensions.DependencyInjection;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Validation
{
  public static class ValidationExtensions
  {
    public static IServiceCollection AddValidators(this IServiceCollection s){ return s; }
  }
}
