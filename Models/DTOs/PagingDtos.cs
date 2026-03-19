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

    // Resultado paginado (alineado a frontend)
    // Recomendación: usar class inmutable o record; aquí dejamos class pero controlado.
    public sealed class PagedResult<T>
    {
        public required List<T> Items { get; init; }
        public required int Page { get; init; }
        public required int PageSize { get; init; }
        public required int TotalCount { get; init; }
        public required int TotalPages { get; init; }
        public required bool HasPreviousPage { get; init; }
        public required bool HasNextPage { get; init; }

        public static PagedResult<T> Create(
            List<T> items,
            int page,
            int pageSize,
            int totalCount)
        {
            var totalPages = totalCount <= 0 ? 0 : (int)Math.Ceiling(totalCount / (double)pageSize);
            var normalizedPage = totalPages > 0 ? Math.Min(Math.Max(page, 1), totalPages) : 1;

            return new PagedResult<T>
            {
                Items = items,
                Page = normalizedPage,
                PageSize = pageSize,
                TotalCount = totalCount,
                TotalPages = totalPages,
                HasPreviousPage = normalizedPage > 1,
                HasNextPage = totalPages > 0 && normalizedPage < totalPages
            };
        }
    }
}
