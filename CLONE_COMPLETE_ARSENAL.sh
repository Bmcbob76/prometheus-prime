#!/bin/bash
# PROMETHEUS PRIME - COMPLETE ARSENAL DEPLOYMENT
# Authority Level: 11.0
# Commander: Bobby Don McWilliams II
# Deploys 150+ offensive security tools from public repositories

set -e

LOG_FILE="ARSENAL_DEPLOYMENT_LOG.txt"
echo "🔥 PROMETHEUS PRIME - ARSENAL DEPLOYMENT STARTED: $(date)" | tee -a $LOG_FILE

# Function to clone with error handling
clone_repo() {
    local url=$1
    local path=$2
    local name=$(basename $path)

    echo "⚡ Cloning $name..." | tee -a $LOG_FILE
    if git clone --depth 1 "$url" "$path" 2>&1 | tee -a $LOG_FILE; then
        # Remove .git to save space
        rm -rf "$path/.git"
        echo "✅ $name deployed" | tee -a $LOG_FILE
        return 0
    else
        echo "❌ $name FAILED" | tee -a $LOG_FILE
        return 1
    fi
}

# ==================== TIER 1: CRITICAL ====================
echo "🎯 TIER 1: CRITICAL EXPLOITATION TOOLS" | tee -a $LOG_FILE

clone_repo "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "PAYLOADS"
clone_repo "https://github.com/danielmiessler/SecLists.git" "SECLISTS"
clone_repo "https://github.com/sqlmapproject/sqlmap.git" "WEB/sqlmap"
clone_repo "https://github.com/s0md3v/XSStrike.git" "WEB/XSStrike"
clone_repo "https://github.com/projectdiscovery/nuclei-templates.git" "NUCLEI_TEMPLATES"

# Post-Exploitation
clone_repo "https://github.com/BC-SECURITY/Empire.git" "EMPIRE"
clone_repo "https://github.com/cobbr/Covenant.git" "COVENANT"
clone_repo "https://github.com/gentilkiwi/mimikatz.git" "MIMIKATZ"

# OSINT & Recon
clone_repo "https://github.com/laramies/theHarvester.git" "OSINT/theHarvester"
clone_repo "https://github.com/sherlock-project/sherlock.git" "OSINT/sherlock"
clone_repo "https://github.com/lanmaster53/recon-ng.git" "OSINT/recon-ng"
clone_repo "https://github.com/smicallef/spiderfoot.git" "OSINT/spiderfoot"

# Network
clone_repo "https://github.com/fortra/impacket.git" "NETWORK/impacket"
clone_repo "https://github.com/lgandx/Responder.git" "NETWORK/Responder"
clone_repo "https://github.com/aircrack-ng/aircrack-ng.git" "WIRELESS/aircrack-ng"

echo "✅ TIER 1 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 2: HIGH VALUE ====================
echo "🎯 TIER 2: HIGH VALUE TOOLS" | tee -a $LOG_FILE

# Cloud & Container
mkdir -p CLOUD MOBILE FORENSICS
clone_repo "https://github.com/RhinoSecurityLabs/pacu.git" "CLOUD/pacu"
clone_repo "https://github.com/BishopFox/cloudfox.git" "CLOUD/cloudfox"
clone_repo "https://github.com/trufflesecurity/trufflehog.git" "CLOUD/trufflehog"

# Mobile
clone_repo "https://github.com/MobSF/Mobile-Security-Framework-MobSF.git" "MOBILE/MobSF"
clone_repo "https://github.com/frida/frida.git" "MOBILE/frida"

# Forensics
clone_repo "https://github.com/volatilityfoundation/volatility3.git" "FORENSICS/volatility3"
clone_repo "https://github.com/sleuthkit/autopsy.git" "FORENSICS/autopsy"

echo "✅ TIER 2 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 3: ACTIVE DIRECTORY ====================
echo "🎯 TIER 3: ACTIVE DIRECTORY DOMINATION" | tee -a $LOG_FILE

mkdir -p AD C2 EVASION
clone_repo "https://github.com/BloodHoundAD/BloodHound.git" "AD/BloodHound"
clone_repo "https://github.com/byt3bl33d3r/CrackMapExec.git" "AD/CrackMapExec"
clone_repo "https://github.com/PowerShellMafia/PowerSploit.git" "AD/PowerSploit"
clone_repo "https://github.com/GhostPack/Rubeus.git" "AD/Rubeus"
clone_repo "https://github.com/BloodHoundAD/SharpHound.git" "AD/SharpHound"
clone_repo "https://github.com/danielbohannon/Invoke-Obfuscation.git" "AD/Invoke-Obfuscation"

echo "✅ TIER 3 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 4: EVASION & C2 ====================
echo "🎯 TIER 4: EVASION & COMMAND AND CONTROL" | tee -a $LOG_FILE

clone_repo "https://github.com/Veil-Framework/Veil.git" "EVASION/Veil"
clone_repo "https://github.com/ParrotSec/shellter.git" "EVASION/shellter"
clone_repo "https://github.com/GreatSCT/GreatSCT.git" "EVASION/GreatSCT"
clone_repo "https://github.com/TheWover/donut.git" "EVASION/donut"
clone_repo "https://github.com/optiv/ScareCrow.git" "EVASION/ScareCrow"

clone_repo "https://github.com/BishopFox/sliver.git" "C2/sliver"
clone_repo "https://github.com/nettitude/PoshC2.git" "C2/PoshC2"
clone_repo "https://github.com/HavocFramework/Havoc.git" "C2/Havoc"
clone_repo "https://github.com/its-a-feature/Mythic.git" "C2/Mythic"
clone_repo "https://github.com/Ne0nd0g/merlin.git" "C2/merlin"

echo "✅ TIER 4 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 5: WEB & API ====================
echo "🎯 TIER 5: WEB APPLICATION ADVANCED" | tee -a $LOG_FILE

mkdir -p API
clone_repo "https://github.com/snoopysecurity/awesome-burp-extensions.git" "WEB/burp-extensions"
clone_repo "https://github.com/commixproject/commix.git" "WEB/commix"
clone_repo "https://github.com/zaproxy/community-scripts.git" "WEB/zap-scripts"
clone_repo "https://github.com/codingo/NoSQLMap.git" "WEB/NoSQLMap"
clone_repo "https://github.com/enjoiz/XXEinjector.git" "WEB/XXEinjector"
clone_repo "https://github.com/graphql-kit/graphql-voyager.git" "WEB/graphql-voyager"

clone_repo "https://github.com/s0md3v/Arjun.git" "API/Arjun"
clone_repo "https://github.com/assetnote/kiterunner.git" "API/kiterunner"
clone_repo "https://github.com/swisskyrepo/GraphQLmap.git" "API/GraphQLmap"

echo "✅ TIER 5 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 6: RECON ====================
echo "🎯 TIER 6: RECONNAISSANCE" | tee -a $LOG_FILE

mkdir -p RECON INTEL
clone_repo "https://github.com/projectdiscovery/subfinder.git" "RECON/subfinder"
clone_repo "https://github.com/owasp-amass/amass.git" "RECON/amass"
clone_repo "https://github.com/blechschmidt/massdns.git" "RECON/massdns"
clone_repo "https://github.com/darkoperator/dnsrecon.git" "RECON/dnsrecon"
clone_repo "https://github.com/aboul3la/Sublist3r.git" "RECON/Sublist3r"
clone_repo "https://github.com/RustScan/RustScan.git" "RECON/RustScan"
clone_repo "https://github.com/projectdiscovery/naabu.git" "RECON/naabu"
clone_repo "https://github.com/scipag/vulscan.git" "RECON/nmap-vulscan"

clone_repo "https://github.com/gitleaks/gitleaks.git" "INTEL/gitleaks"
clone_repo "https://github.com/michenriksen/gitrob.git" "INTEL/gitrob"
clone_repo "https://github.com/eth0izzle/shhgit.git" "INTEL/shhgit"
clone_repo "https://github.com/hisxo/gitGraber.git" "INTEL/gitGraber"

echo "✅ TIER 6 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 7: PASSWORDS ====================
echo "🎯 TIER 7: PASSWORD CRACKING" | tee -a $LOG_FILE

mkdir -p PASSWORDS
clone_repo "https://github.com/hashcat/hashcat.git" "PASSWORDS/hashcat"
clone_repo "https://github.com/openwall/john.git" "PASSWORDS/john"
clone_repo "https://github.com/digininja/CeWL.git" "PASSWORDS/CeWL"
clone_repo "https://github.com/Mebus/cupp.git" "PASSWORDS/cupp"
clone_repo "https://github.com/sc0tfree/mentalist.git" "PASSWORDS/mentalist"
clone_repo "https://github.com/digininja/pipal.git" "PASSWORDS/pipal"
clone_repo "https://github.com/digininja/RSMangler.git" "PASSWORDS/RSMangler"
clone_repo "https://github.com/x90skysn3k/brutespray.git" "PASSWORDS/brutespray"
clone_repo "https://github.com/lanjelot/patator.git" "PASSWORDS/patator"

echo "✅ TIER 7 COMPLETE" | tee -a $LOG_FILE

# ==================== TIER 8: SOCIAL ENGINEERING ====================
echo "🎯 TIER 8: SOCIAL ENGINEERING" | tee -a $LOG_FILE

mkdir -p SOCIAL
clone_repo "https://github.com/trustedsec/social-engineer-toolkit.git" "SOCIAL/SET"
clone_repo "https://github.com/gophish/gophish.git" "SOCIAL/gophish"
clone_repo "https://github.com/rsmusllp/king-phisher.git" "SOCIAL/king-phisher"
clone_repo "https://github.com/kgretzky/evilginx2.git" "SOCIAL/evilginx2"
clone_repo "https://github.com/ustayready/CredSniper.git" "SOCIAL/CredSniper"
clone_repo "https://github.com/UndeadSec/SocialFish.git" "SOCIAL/SocialFish"
clone_repo "https://github.com/DarkSecDevelopers/HiddenEye.git" "SOCIAL/HiddenEye"
clone_repo "https://github.com/htr-tech/zphisher.git" "SOCIAL/zphisher"

echo "✅ TIER 8 COMPLETE" | tee -a $LOG_FILE

echo "🔥 ARSENAL DEPLOYMENT COMPLETE: $(date)" | tee -a $LOG_FILE
echo "📊 Check ARSENAL_DEPLOYMENT_LOG.txt for details" | tee -a $LOG_FILE
