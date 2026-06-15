namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd
{
    public sealed class LocalAdOptions
    {
        public const string Section = "LocalAd";

        /// <summary>Ej: ldap://dc01.uta.edu.ec o ldaps://dc01.uta.edu.ec:636</summary>
        public string Server { get; set; } = "";

        /// <summary>Puerto LDAP (389) o LDAPS (636).</summary>
        public int Port { get; set; } = 389;

        /// <summary>Puerto LDAPS para operaciones que requieren SSL (unicodePwd). Default: 636.</summary>
        public int LdapsPort { get; set; } = 636;

        /// <summary>Base DN de búsqueda, ej: DC=uta,DC=edu,DC=ec</summary>
        public string BaseDn { get; set; } = "";

        /// <summary>DN de la cuenta de servicio, ej: CN=svc-auth,OU=ServiceAccounts,DC=uta,DC=edu,DC=ec</summary>
        public string ServiceAccountDn { get; set; } = "";

        /// <summary>Contraseña de la cuenta de servicio. Debe venir de variable de entorno.</summary>
        public string ServiceAccountPassword { get; set; } = "";

        /// <summary>Timeout de conexión LDAP en segundos.</summary>
        public int TimeoutSeconds { get; set; } = 10;

        /// <summary>OU para funcionarios activos, ej: OU=Activos,OU=USUARIOS,DC=uta,DC=edu,DC=ec</summary>
        public string FuncionariosActivosOu { get; set; } = "";

        /// <summary>OU para funcionarios inactivos, ej: OU=Inactivos,OU=USUARIOS,DC=uta,DC=edu,DC=ec</summary>
        public string FuncionariosInactivosOu { get; set; } = "";

        /// <summary>OU para estudiantes activos, ej: OU=Activos,OU=ESTUDIANTES,DC=uta,DC=edu,DC=ec</summary>
        public string EstudiantesActivosOu { get; set; } = "";

        /// <summary>OU para estudiantes inactivos, ej: OU=Inactivos,OU=ESTUDIANTES,DC=uta,DC=edu,DC=ec</summary>
        public string EstudiantesInactivosOu { get; set; } = "";

        /// <summary>OU donde se crean grupos, ej: OU=Grupos,DC=uta,DC=edu,DC=ec</summary>
        public string GroupsOu { get; set; } = "";

        /// <summary>Dominio NetBIOS, ej: UTA. Usado para construir el UPN en el bind.</summary>
        public string NetBiosDomain { get; set; } = "";
    }
}
