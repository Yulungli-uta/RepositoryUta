namespace WsSeguUta.AuthSystem.API.Models.DTOs
{
    // Request paginado (alineado a frontend)
    public sealed class PagedRequestDto
    {
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 20;
        public string? SortBy { get; set; }
        public string? SortDirection { get; set; } = "asc"; // "asc" | "desc"
        public string? Search { get; set; } // opcional

        public void Normalize(int maxPageSize = 200)
        {
            if (Page < 1) Page = 1;
            if (PageSize < 1) PageSize = 20;
            if (PageSize > maxPageSize) PageSize = maxPageSize;
            SortDirection = (SortDirection ?? "asc").Trim().ToLowerInvariant();
            SortBy = SortBy?.Trim();
            Search = Search?.Trim();
        }
    }

    /// <summary>
    /// Resultado genérico paginado. TotalPages, HasPreviousPage y HasNextPage
    /// se calculan automáticamente a partir de TotalCount y PageSize.
    /// </summary>
    public sealed class PagedResult<T>
    {
        public required IReadOnlyList<T> Items { get; init; }
        public required int Page { get; init; }
        public required int PageSize { get; init; }
        public required long TotalCount { get; init; }

        public int TotalPages => PageSize > 0 ? (int)Math.Ceiling((double)TotalCount / PageSize) : 0;
        public bool HasPreviousPage => Page > 1;
        public bool HasNextPage => Page < TotalPages;

        /// <summary>Resultado vacío para la página solicitada.</summary>
        public static PagedResult<T> Empty(int page, int pageSize) => new()
        {
            Items = [],
            Page = page,
            PageSize = pageSize,
            TotalCount = 0
        };

        /// <summary>Crea un resultado paginado con los datos proporcionados.</summary>
        public static PagedResult<T> Create(IReadOnlyList<T> items, int page, int pageSize, long totalCount) => new()
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };
    }
}
