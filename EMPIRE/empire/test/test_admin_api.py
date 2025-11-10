import pytest
from starlette.status import HTTP_200_OK


@pytest.fixture(scope="module", autouse=True)
def _set_ip_filtering(main):
    main.ipsv2.ip_filtering = False
    yield
    main.ipsv2.ip_filtering = True


def test_toggle_ip_filtering(client, admin_auth_header, main):
    resp = client.put(
        "/api/v2/admin/ip_filtering?enabled=true",
        headers=admin_auth_header,
    )

    assert resp.status_code == HTTP_200_OK
    assert main.ipsv2.ip_filtering is True

    resp = client.put(
        "/api/v2/admin/ip_filtering?enabled=false",
        headers=admin_auth_header,
    )

    assert resp.status_code == HTTP_200_OK
    assert main.ipsv2.ip_filtering is False
