import netaddr
import pytest

from empire.server.common.empire import MainMenu
from empire.server.core.db import models
from empire.server.core.db.models import IpList


@pytest.fixture(scope="module")
def ip_service(main: MainMenu):
    return main.ipsv2


def to_set(ip_service, ip_list, list_type=IpList.allow):
    ip_list = [models.IP(ip_address=ip, list=list_type) for ip in ip_list]
    return ip_service._to_ip_set(ip_list)


def test__ip_is_in(ip_service):
    ip_set = to_set(ip_service, ["192.168.0.1", "192.168.0.2"])
    assert ip_service._ip_is_in("192.168.0.1", ip_set) is True

    ip_set = to_set(ip_service, ["192.168.0.1", "192.168.0.2"])
    assert ip_service._ip_is_in("192.168.0.5", ip_set) is False

    ip_set = to_set(ip_service, ["10.0.0.42/32"])
    assert ip_service._ip_is_in("10.0.0.42", ip_set) is True

    ip_set = to_set(ip_service, ["10.0.0.42/32"])
    assert ip_service._ip_is_in("10.0.0.41", ip_set) is False

    ip_set = to_set(ip_service, ["10.0.0.42/32"])
    assert ip_service._ip_is_in("10.0.0.43", ip_set) is False

    ip_set = to_set(ip_service, ["10.0.0.128-10.10.10.10"])
    assert ip_service._ip_is_in("10.0.0.1", ip_set) is False

    ip_set = to_set(ip_service, ["10.0.0.128-10.10.10.10"])
    assert ip_service._ip_is_in("192.168.0.1", ip_set) is False

    ip_set = to_set(ip_service, ["2001:db8::1"])
    assert ip_service._ip_is_in("2001:db8::1", ip_set) is True

    ip_set = to_set(ip_service, ["2001:db8::1"])
    assert ip_service._ip_is_in("2001:db8::2", ip_set) is False

    ip_set = to_set(ip_service, ["2001:db8::1/128"])
    assert ip_service._ip_is_in("2001:db8::1", ip_set) is True

    ip_set = to_set(ip_service, ["2001:db8::1/128"])
    assert ip_service._ip_is_in("2001:db8::1", ip_set) is True

    ip_set = to_set(ip_service, ["2001:db8::1/32"])
    assert ip_service._ip_is_in("2001:db8::1", ip_set) is True


def test_is_ip_allowed_empty(ip_service):
    ip_service.allow_list = ip_service._to_ip_set([])
    ip_service.deny_list = ip_service._to_ip_set([])

    assert ip_service.is_ip_allowed("1.1.1.1") is True


def test_is_ip_allowed_allow(ip_service):
    ip_service.allow_list = to_set(ip_service, ["192.168.0.0"], IpList.allow)
    ip_service.deny_list = to_set(ip_service, [], IpList.deny)

    assert ip_service.is_ip_allowed("192.168.0.0") is True
    assert ip_service.is_ip_allowed("192.168.0.1") is False


def test_is_ip_allowed_deny(ip_service):
    ip_service.allow_list = to_set(ip_service, [], IpList.allow)
    ip_service.deny_list = to_set(ip_service, ["192.168.0.0"], IpList.deny)

    assert ip_service.is_ip_allowed("192.168.0.0") is False
    assert ip_service.is_ip_allowed("192.168.0.1") is True


def test_is_ip_allowed_allow_deny(ip_service):
    ip_service.allow_list = to_set(ip_service, ["192.168.0.0"], IpList.allow)
    ip_service.deny_list = to_set(ip_service, ["192.168.0.1"], IpList.deny)

    assert ip_service.is_ip_allowed("192.168.0.0") is True
    assert ip_service.is_ip_allowed("192.168.0.1") is False
    assert ip_service.is_ip_allowed("192.168.0.2") is False

    ip_service.deny_list.add(netaddr.IPAddress("192.168.0.0"))

    assert ip_service.is_ip_allowed("192.168.0.0") is False

    ip_service.allow_list = to_set(
        ip_service, ["192.168.1.1-192.168.1.255"], IpList.allow
    )
    ip_service.deny_list = to_set(ip_service, ["192.168.1.5"], IpList.deny)

    assert ip_service.is_ip_allowed("192.168.1.1") is True  # in allow list
    assert (
        ip_service.is_ip_allowed("192.168.1.5") is False
    )  # in allow list, but also in deny list
    assert ip_service.is_ip_allowed("192.168.8.8") is False  # In neither list
