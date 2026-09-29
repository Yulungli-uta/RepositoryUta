from repositoryuta.core.pagination import PagedResult, clamp_page_params


def test_clamp_page_params_normalizes_out_of_range_values() -> None:
    assert clamp_page_params(0, 0) == (1, 1)
    assert clamp_page_params(-5, 999) == (1, 200)
    assert clamp_page_params(3, 50) == (3, 50)


def test_paged_result_empty() -> None:
    result = PagedResult[int].empty(page=2, page_size=20)

    assert result.items == []
    assert result.total_count == 0
    assert result.page == 2
