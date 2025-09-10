# Centralizador de Autenticación y Autorización

## 📋 Resumen de Cambios Implementados

Este documento describe las modificaciones realizadas para convertir el sistema actual en un **Centralizador de Autenticación y Autorización** para sistemas legacy.

## 🗄️ Cambios en Base de Datos

### Nuevas Tablas Creadas

1. **`auth.tbl_Applications`** - Registro de aplicaciones cliente
2. **`auth.tbl_ApplicationTokens`** - Tokens de acceso para aplicaciones
3. **`auth.tbl_LegacyAuthLog`** - Log específico de autenticaciones legacy

### Script SQL
- **Archivo:** `Database/centralizador_auth_changes.sql`
- **Descripción:** Contiene todas las modificaciones SQL necesarias
- **Incluye:** Tablas, procedimientos almacenados, vistas y datos de ejemplo

## 🏗️ Cambios en el Código

### Nuevas Entidades
- `Application` - Aplicaciones cliente registradas
- `ApplicationToken` - Tokens de aplicaciones
- `LegacyAuthLog` - Log de autenticaciones legacy

### Nuevos DTOs
- `CreateApplicationDto`, `UpdateApplicationDto`
- `LegacyAuthRequest`, `LegacyAuthResponse`
- `ValidateTokenRequest`, `ValidateTokenResponse`
- `AppAuthRequest`, `AppAuthResponse`

### Nuevos Controladores
- **`AppAuthController`** - Maneja la autenticación de aplicaciones y usuarios legacy
  - `POST /api/app-auth/token` - Autenticar aplicación
  - `POST /api/app-auth/legacy-login` - Login de usuario legacy
  - `POST /api/app-auth/validate-token` - Validar token
  - `GET /api/app-auth/stats/{clientId}` - Estadísticas de aplicación

### Controladores Modificados
- **`AuthController`** - Agregado endpoint `POST /api/auth/validate-token`

### Nuevos Servicios
- **`IAppAuthService`** / **`AppAuthService`** - Lógica de negocio del centralizador

### Servicios Modificados
- **`IAuthService`** / **`AuthService`** - Agregado método `ValidateTokenAsync`

## 🚀 Pasos de Implementación

### 1. Ejecutar Script de Base de Datos
```sql
-- Ejecutar en SQL Server Management Studio o herramienta similar
-- Archivo: Database/centralizador_auth_changes.sql
```

### 2. Crear y Ejecutar Migración de Entity Framework
```bash
# En la carpeta del proyecto
dotnet ef migrations add AddCentralizadorEntities
dotnet ef database update
```

### 3. Compilar y Probar
```bash
dotnet build
dotnet run
```

## 📡 Endpoints Disponibles

### Autenticación de Aplicaciones
```http
POST /api/app-auth/token
Content-Type: application/json

{
  "clientId": "legacy-erp-client",
  "clientSecret": "erp-secret-key-2024"
}
```

### Autenticación Legacy de Usuarios
```http
POST /api/app-auth/legacy-login
Content-Type: application/json

{
  "clientId": "legacy-erp-client",
  "clientSecret": "erp-secret-key-2024",
  "userEmail": "usuario@empresa.com",
  "password": "contraseña123",
  "includePermissions": true
}
```

### Validación de Tokens
```http
POST /api/app-auth/validate-token
Content-Type: application/json

{
  "token": "guid-del-token",
  "clientId": "legacy-erp-client"
}
```

## 🔧 Aplicaciones de Ejemplo Creadas

El script SQL incluye 3 aplicaciones de ejemplo:

1. **Sistema Legacy ERP**
   - ClientId: `legacy-erp-client`
   - Secret: `erp-secret-key-2024`

2. **Portal Web Empleados**
   - ClientId: `employee-portal-client`
   - Secret: `portal-secret-2024`

3. **API Microservicio Reportes**
   - ClientId: `reports-api-client`
   - Secret: `reports-api-secret-2024`

## 🔐 Flujo de Autenticación

### Para Sistemas Legacy

1. **Autenticación de Aplicación:**
   - El sistema legacy se autentica con `clientId` y `clientSecret`
   - Recibe un token de aplicación válido por tiempo configurado

2. **Autenticación de Usuario:**
   - El sistema legacy envía credenciales del usuario junto con sus propias credenciales
   - Recibe información del usuario, roles y permisos si la autenticación es exitosa

3. **Validación de Tokens:**
   - Los microservicios pueden validar tokens JWT enviando el token al centralizador
   - Reciben información sobre la validez y datos del usuario/aplicación

## 📊 Monitoreo y Auditoría

- **Logs detallados** en `auth.tbl_LegacyAuthLog`
- **Estadísticas de uso** por aplicación
- **Auditoría completa** de intentos de autenticación
- **Rate limiting** configurado para prevenir ataques

## ⚙️ Configuración

### Parámetros Agregados
- `Centralizador.Enabled` - Habilitar funcionalidad
- `Centralizador.DefaultTokenExpiration` - Expiración por defecto
- `Centralizador.MaxApplications` - Máximo de aplicaciones
- `Centralizador.LogRetentionDays` - Retención de logs
- `Centralizador.RateLimitPerMinute` - Límite de requests

## 🔍 Próximos Pasos

1. **Ejecutar el script SQL** en la base de datos
2. **Compilar y probar** la aplicación
3. **Configurar las aplicaciones cliente** según necesidades
4. **Implementar la integración** en los sistemas legacy
5. **Monitorear los logs** para verificar funcionamiento

## 📞 Soporte

Para dudas o problemas con la implementación, revisar:
- Los logs de la aplicación
- La tabla `auth.tbl_LegacyAuthLog` para auditoría
- Los endpoints de estadísticas para monitoreo

