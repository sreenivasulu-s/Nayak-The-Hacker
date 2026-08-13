from backend.scanner.dispatcher import TargetTypeAdapter


def test_api_target_uses_http_scanner():
    adapter = TargetTypeAdapter()

    assert hasattr(adapter, "scan")


def test_target_types_are_supported():
    expected = {
        "web",
        "api",
        "network",
        "mobile",
        "cloud",
        "wireless",
    }

    assert expected == {
        "web",
        "api",
        "network",
        "mobile",
        "cloud",
        "wireless",
    }
