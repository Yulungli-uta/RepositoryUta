# Azure AD Management - Documentación

## 🎯 Descripción

Este módulo agrega funcionalidades completas de gestión administrativa de Azure Active Directory a tu sistema de autenticación.

## ✨ Funcionalidades Implementadas

### 1. Gestión de Usuarios en Azure AD
- ✅ Crear usuarios
- ✅ Obtener usuario por ID o email
- ✅ Actualizar información de usuarios
- ✅ Habilitar/Deshabilitar cuentas
- ✅ Eliminar usuarios
- ✅ Listar usuarios con paginación

### 2. Gestión de Contraseñas
- ✅ Resetear contraseñas (genera contraseña temporal)
- ✅ Cambiar contraseñas
- ✅ Validar políticas de contraseñas
- ✅ Generar contraseñas seguras automáticamente

### 3. Gestión de Roles de Directorio de Azure AD
- ✅ Listar todos los roles de directorio
- ✅ Obtener roles asignados a un usuario
- ✅ Asignar roles a usuarios
- ✅ Remover roles de usuarios
- ✅ Obtener miembros de un rol

### 4. Gestión de Grupos de Azure AD
- ✅ Crear grupos (Security y Microsoft 365)
- ✅ Obtener información de grupos
- ✅ Actualizar grupos
- ✅ Eliminar grupos
- ✅ Listar grupos con paginación
- ✅ Agregar usuarios a grupos
- ✅ Remover usuarios de grupos
- ✅ Obtener miembros de un grupo
- ✅ Obtener grupos de un usuario

### 5. Operaciones Masivas
- ✅ Creación masiva de usuarios
- ✅ Agregar múltiples usuarios a un grupo

### 6. Sincronización
- ✅ Sincronizar usuarios de Azure AD con base de datos local
- ✅ Logs detallados de sincronización
- ✅ Auditoría completa de operaciones

---

## 📦 Archivos Agregados/Modificados

### **Archivos NUEVOS:**
1. `/Controllers/AzureManagementController.cs` - Controlador con 30+ endpoints
2. `/Services/Implementations/AzureManagementService.cs` - Servicio completo (~1300 líneas)

### **Archivos MODIFICADOS:**
1. `/Models/DTOs/_Dtos.cs` - DTOs agregados al final
2. `/Data/Repositories/_Specialized.cs` - Repositorio Azure AD agregado al final
3. `/Services/Interfaces/_All.cs` - Interfaz agregada al final
4. `/Program.cs` - Registros de servicios agregados
5. `/WsSeguUta.AuthSystem.API.csproj` - Paquete Azure.Identity agregado

---

## ⚙️ Configuración Requerida

### **1. Instalar Dependencias**

El paquete `Azure.Identity` ya está agregado al `.csproj`. Solo necesitas restaurar:

```bash
dotnet restore
```

### **2. Configurar Azure AD en appsettings.json**

Asegúrate de que tu archivo `Configuration/appsettings.json` tenga la configuración de Azure AD:

```json
{
  "AzureAd": {
    "TenantId": "tu-tenant-id",
    "ClientId": "tu-client-id",
    "ClientSecret": "tu-client-secret",
    "RedirectUri": "http://localhost:5010/api/auth/azure/callback"
  }
}
```

### **3. Configurar Permisos en Azure Portal**

**IMPORTANTE**: Requiere permisos de **Global Administrator** en Azure AD.

#### **Pasos:**

1. Ve a [Azure Portal](https://portal.azure.com)
2. Azure Active Directory → App registrations
3. Selecciona tu aplicación registrada
4. Ve a **API permissions**
5. Click en **Add a permission** → **Microsoft Graph**
6. Selecciona **Application permissions** (NO Delegated)
7. Agrega los siguientes permisos:
   - `User.ReadWrite.All`
   - `Directory.ReadWrite.All`
   - `RoleManagement.ReadWrite.Directory`
   - `Group.ReadWrite.All`
   - `GroupMember.ReadWrite.All`
8. Click en **Grant admin consent for [Tu Organización]** (botón azul)
9. Confirma el consentimiento

**Nota**: Sin estos permisos, las operaciones de escritura en Azure AD fallarán.

---

## 🚀 Endpoints Disponibles

### **Base URL**: `/api/azure-management`

**Autenticación**: Todos los endpoints requieren:
- Token JWT válido
- Rol "Admin" asignado al usuario

---

### **Gestión de Usuarios**

#### Crear Usuario
```http
POST /api/azure-management/users
Content-Type: application/json
Authorization: Bearer {token}

{
  "email": "nuevo.usuario@empresa.com",
  "displayName": "Nuevo Usuario",
  "givenName": "Nuevo",
  "surname": "Usuario",
  "password": "TempPassword123!",
  "forceChangePasswordNextSignIn": true,
  "jobTitle": "Desarrollador",
  "department": "IT",
  "usageLocation": "MX"
}
```

#### Obtener Usuario por ID
```http
GET /api/azure-management/users/{azureObjectId}
Authorization: Bearer {token}
```

#### Obtener Usuario por Email
```http
GET /api/azure-management/users/by-email/{email}
Authorization: Bearer {token}
```

#### Actualizar Usuario
```http
PUT /api/azure-management/users/{azureObjectId}
Content-Type: application/json
Authorization: Bearer {token}

{
  "displayName": "Nombre Actualizado",
  "jobTitle": "Senior Developer",
  "department": "IT"
}
```

#### Habilitar Usuario
```http
POST /api/azure-management/users/{azureObjectId}/enable
Authorization: Bearer {token}
```

#### Deshabilitar Usuario
```http
POST /api/azure-management/users/{azureObjectId}/disable
Authorization: Bearer {token}
```

#### Eliminar Usuario
```http
DELETE /api/azure-management/users/{azureObjectId}?permanent=false
Authorization: Bearer {token}
```

#### Listar Usuarios
```http
GET /api/azure-management/users?page=1&pageSize=50
Authorization: Bearer {token}
```

---

### **Gestión de Contraseñas**

#### Resetear Contraseña
```http
POST /api/azure-management/users/{azureObjectId}/reset-password?forceChange=true
Authorization: Bearer {token}
```

**Respuesta:**
```json
{
  "success": true,
  "data": {
    "temporaryPassword": "Abc123!@#Xyz",
    "forceChangeNextSignIn": true,
    "message": "Contraseña reseteada exitosamente"
  }
}
```

#### Cambiar Contraseña
```http
POST /api/azure-management/users/{azureObjectId}/change-password
Content-Type: application/json
Authorization: Bearer {token}

{
  "newPassword": "NuevaPassword123!",
  "forceChangeNextSignIn": false
}
```

#### Validar Contraseña
```http
POST /api/azure-management/validate-password
Content-Type: application/json
Authorization: Bearer {token}

"MiPassword123!"
```

#### Generar Contraseña Segura
```http
GET /api/azure-management/generate-password
Authorization: Bearer {token}
```

---

### **Gestión de Roles de Azure AD**

#### Listar Todos los Roles de Directorio
```http
GET /api/azure-management/azure-roles
Authorization: Bearer {token}
```

#### Obtener Roles de un Usuario
```http
GET /api/azure-management/users/{azureObjectId}/azure-roles
Authorization: Bearer {token}
```

#### Asignar Rol a Usuario
```http
POST /api/azure-management/users/{userId}/azure-roles/{roleId}
Authorization: Bearer {token}
```

#### Remover Rol de Usuario
```http
DELETE /api/azure-management/users/{userId}/azure-roles/{roleId}
Authorization: Bearer {token}
```

#### Obtener Miembros de un Rol
```http
GET /api/azure-management/azure-roles/{roleId}/members
Authorization: Bearer {token}
```

---

### **Gestión de Grupos**

#### Crear Grupo
```http
POST /api/azure-management/groups
Content-Type: application/json
Authorization: Bearer {token}

{
  "displayName": "Grupo IT",
  "description": "Grupo de tecnología",
  "groupType": "Security",
  "securityEnabled": true,
  "mailEnabled": false
}
```

#### Obtener Grupo
```http
GET /api/azure-management/groups/{groupId}
Authorization: Bearer {token}
```

#### Actualizar Grupo
```http
PUT /api/azure-management/groups/{groupId}
Content-Type: application/json
Authorization: Bearer {token}

{
  "displayName": "Nuevo Nombre",
  "description": "Nueva descripción"
}
```

#### Eliminar Grupo
```http
DELETE /api/azure-management/groups/{groupId}
Authorization: Bearer {token}
```

#### Listar Grupos
```http
GET /api/azure-management/groups?page=1&pageSize=50
Authorization: Bearer {token}
```

#### Agregar Usuario a Grupo
```http
POST /api/azure-management/groups/{groupId}/members/{userId}
Authorization: Bearer {token}
```

#### Remover Usuario de Grupo
```http
DELETE /api/azure-management/groups/{groupId}/members/{userId}
Authorization: Bearer {token}
```

#### Obtener Miembros de un Grupo
```http
GET /api/azure-management/groups/{groupId}/members
Authorization: Bearer {token}
```

#### Obtener Grupos de un Usuario
```http
GET /api/azure-management/users/{azureObjectId}/azure-groups
Authorization: Bearer {token}
```

---

### **Operaciones Masivas**

#### Crear Múltiples Usuarios
```http
POST /api/azure-management/users/bulk-create
Content-Type: application/json
Authorization: Bearer {token}

[
  {
    "email": "usuario1@empresa.com",
    "displayName": "Usuario 1",
    "givenName": "Usuario",
    "surname": "Uno",
    "password": "Pass123!",
    "forceChangePasswordNextSignIn": true
  },
  {
    "email": "usuario2@empresa.com",
    "displayName": "Usuario 2",
    "givenName": "Usuario",
    "surname": "Dos",
    "password": "Pass456!",
    "forceChangePasswordNextSignIn": true
  }
]
```

#### Agregar Múltiples Usuarios a Grupo
```http
POST /api/azure-management/groups/{groupId}/members/bulk-add
Content-Type: application/json
Authorization: Bearer {token}

[
  "user-id-1",
  "user-id-2",
  "user-id-3"
]
```

---

### **Sincronización**

#### Sincronizar Usuario con BD Local
```http
POST /api/azure-management/sync/user/{azureObjectId}
Authorization: Bearer {token}
```

---

## 🔐 Seguridad

### **Autenticación**
- Todos los endpoints requieren token JWT válido
- Solo usuarios con rol "Admin" pueden acceder

### **Auditoría**
- Todas las operaciones se registran en `auth.tbl_AuditLog`
- Incluye: usuario que ejecutó, acción, timestamp, valores anteriores/nuevos

### **Sincronización**
- Usuarios creados en Azure AD se sincronizan automáticamente con BD local
- Tabla `auth.tbl_Users` mantiene vínculo con campo `AzureObjectId`
- Logs en `auth.tbl_AzureSyncLog`

---

## 📊 Tablas Utilizadas

### **Existentes (No modificadas):**
- `auth.tbl_Users` - Almacena usuarios con campo `AzureObjectId`
- `auth.tbl_AzureSyncLog` - Logs de sincronización
- `auth.tbl_AuditLog` - Auditoría de operaciones

**Nota**: NO se crearon nuevas tablas. Los roles y grupos de Azure AD se consultan en tiempo real vía Microsoft Graph API.

---

## 🔄 Flujo de Datos

### **Crear Usuario:**
1. Admin envía request a `/api/azure-management/users`
2. Servicio valida datos y contraseña
3. Llama a Microsoft Graph API para crear usuario en Azure AD
4. Azure AD retorna usuario creado
5. Se sincroniza con BD local (`auth.tbl_Users`)
6. Se registra en logs (`auth.tbl_AzureSyncLog`, `auth.tbl_AuditLog`)
7. Retorna respuesta al admin

### **Asignar Rol:**
1. Admin envía request a `/api/azure-management/users/{userId}/azure-roles/{roleId}`
2. Servicio llama a Microsoft Graph API
3. Azure AD asigna el rol
4. Se registra en auditoría (`auth.tbl_AuditLog`)
5. **NO se guarda en BD local** (el rol vive en Azure AD)
6. Para consultar roles: se consulta en tiempo real a Microsoft Graph

---

## ⚠️ Notas Importantes

### **Roles Locales vs Roles de Azure AD**

| Aspecto | Roles Locales | Roles de Azure AD |
|---------|---------------|-------------------|
| **Dónde viven** | `auth.tbl_Roles` | Azure Active Directory |
| **Cómo se asignan** | `INSERT INTO auth.tbl_UserRoles` | Microsoft Graph API |
| **Ejemplos** | "Admin", "Usuario" | "Global Admin", "User Admin" |
| **Controlan acceso a** | Tu aplicación | Microsoft 365 y Azure |

**Ambos sistemas conviven**: Un usuario puede tener roles locales Y roles de Azure AD.

### **Permisos Requeridos**
- Los permisos de **Application** son diferentes a los **Delegated**
- **Application permissions**: La aplicación actúa por sí misma (lo que necesitamos)
- **Delegated permissions**: La aplicación actúa en nombre de un usuario

### **Límites de Rate**
- Microsoft Graph API tiene límites de tasa (throttling)
- Para operaciones masivas, considera implementar retry logic
- Límite aproximado: 2000 requests por minuto por aplicación

---

## 🧪 Pruebas

### **Ejemplo con cURL:**

```bash
# 1. Login como Admin
curl -X POST http://localhost:5010/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@empresa.com",
    "password": "tu-password"
  }'

# Guarda el accessToken de la respuesta

# 2. Crear usuario en Azure AD
curl -X POST http://localhost:5010/api/azure-management/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {accessToken}" \
  -d '{
    "email": "test@empresa.com",
    "displayName": "Usuario Test",
    "givenName": "Usuario",
    "surname": "Test",
    "password": "TestPass123!",
    "forceChangePasswordNextSignIn": true,
    "usageLocation": "MX"
  }'

# 3. Listar usuarios
curl -X GET "http://localhost:5010/api/azure-management/users?page=1&pageSize=10" \
  -H "Authorization: Bearer {accessToken}"
```

---

## 🐛 Troubleshooting

### **Error: "Azure AD configuration is missing"**
- Verifica que `AzureAd:TenantId`, `AzureAd:ClientId` y `AzureAd:ClientSecret` estén en appsettings.json

### **Error: "Insufficient privileges to complete the operation"**
- Verifica que los permisos de aplicación estén configurados en Azure Portal
- Asegúrate de haber hecho "Grant admin consent"

### **Error: "The user or administrator has not consented"**
- Necesitas consentimiento de administrador para los permisos de aplicación

### **Error al compilar**
- Ejecuta `dotnet restore` para instalar dependencias
- Verifica que el paquete `Azure.Identity` esté en el .csproj

---

## 📚 Referencias

- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure AD Application Permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Azure Identity SDK](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme)

---

## ✅ Checklist de Implementación

- [x] DTOs creados
- [x] Repositorio Azure AD creado
- [x] Servicio implementado
- [x] Controlador creado
- [x] Servicios registrados en Program.cs
- [x] Paquete Azure.Identity agregado
- [x] Documentación creada
- [ ] Configurar permisos en Azure Portal (responsabilidad del usuario)
- [ ] Compilar y probar

---

## 👤 Autor

Implementado por Manus AI - Diciembre 2024
