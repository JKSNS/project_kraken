from kraken.orchestrator import _merge_state_update


def test_merge_state_update_appends_additive_fields():
    existing = {
        "strategies_tried": ["s1"],
        "solve_scripts": [{"attempt_num": 1}],
        "flag": "",
    }
    update = {
        "strategies_tried": ["s2"],
        "solve_scripts": [{"attempt_num": 2}],
        "flag": "flag{ok}",
    }

    merged = _merge_state_update(existing, update)

    assert merged["strategies_tried"] == ["s1", "s2"]
    assert [x["attempt_num"] for x in merged["solve_scripts"]] == [1, 2]
    assert merged["flag"] == "flag{ok}"


def test_merge_state_update_replaces_non_list_values():
    existing = {"current_strategy": "a", "iteration_count": 1}
    update = {"current_strategy": "b", "iteration_count": 2}

    merged = _merge_state_update(existing, update)

    assert merged["current_strategy"] == "b"
    assert merged["iteration_count"] == 2
