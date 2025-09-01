
rule NCSCNL_CitrixIncident2025_91107190236 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "91.107.190.236"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_88119169150 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "88.119.169.150"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_386024599 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "38.60.245.99"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_1019991107 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "101.99.91.107"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_845567133 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "84.55.67.133"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_19436375 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "194.36.37.5"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_logonLogonPointindexphp {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "logon/LogonPoint/index.php"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_logonLogonPointtmindexphp {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "logon/LogonPoint/tmindex.php"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_logonLogonPointLogonUIphp {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "logon/LogonPoint/LogonUI.php"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_logonLogonPointpluginindexphp {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "logon/LogonPoint/plugin_index.php"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_Mozilla50WindowsNT100Win64x64AppleWebKit53736KHTMLlikeGeckoChrome12206261112Safari53736 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-19"

    strings:
        $s = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_python3c {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "python3 -c"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_base64b85decode {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "base64.b85decode"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_base64b64decode {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "base64.b64decode"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_zlibdecompress {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "zlib.decompress"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_toucht {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "touch -t"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_apachectlgraceful {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "apachectl graceful"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_vartmpsh {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "/var/tmp/sh"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_HUNTING_1245184 {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "medium"
        tlp = "CLEAR"
        date = "2025-08-19"

    strings:
        $s = "1245184"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_hspmtrav {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "hs/pmt/rav/"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_fnocdptth {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "fnoc.dptth"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_galfphp {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "galf_php"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_hctaMselif {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "hctaMselif"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_lufecarg {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "lufecarg"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_phpIUnogoL {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "php.IUnogoL"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_relacstencrgifnocsn {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "relacsten.cr/gifnocsn"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_tnioPnogoL {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "tnioPnogoL"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_phpxednimt {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "php.xednimt"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_ltcehcapa {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "ltcehcapa"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_gifnocsn {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "gifnocsn"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_nsrootactions {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-08-06"

    strings:
        $s = "\"nsroot\", \"actions\":"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_HUNTING_nfauthdoDialoguedo {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "low"
        tlp = "CLEAR"
        date = "2025-08-19"

    strings:
        $s = "/nf/auth/doDialogue.do"
    
    condition:
        any of them
}

rule NCSCNL_CitrixIncident2025_ropchain {
    meta:
        author = "NCSC-NL"
        author_url = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
        confidence_level = "high"
        tlp = "CLEAR"
        date = "2025-09-01"

    strings:
        $s = { 
            ?? ?? ?? 00 00 00 00 00 
            ?? ?? ?? 01 00 00 00 00
            ?? ?? ?? 00 00 00 00 00
            ?? ?? ?? 03 00 00 00 00
            ?? ?? ?? 00 00 00 00 00
            ?? ?? ?? 03 00 00 00 00
            ?? ?? ?? 01 00 00 00 00
            ?? ?? ?? 0? 00 00 00 00
            ?? ?? ?? ?? 00 00 00 00
            ?? ?? ?? ?? 00 00 00 00
            ?? ?? ?? ?? 00 00 00 00
            ?? ?? ?? ?? ?? ?? ?? ??
        }
    
    condition:
        any of them
}
