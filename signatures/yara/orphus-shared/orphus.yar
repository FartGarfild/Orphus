/*
   Orphus AV Scanner — shared rules from real incidents.
   Refreshed by "av.sh -u" from the Oprhus-patched branch of
   github.com/FartGarfild/Orphus. Do not edit locally (overwritten).
*/

rule Orphus_PHP_Webshell_Eval_Request_Tiny
{
    meta:
        description = "Tiny PHP file that evals a request parameter (one-line webshell)"
        author = "Orphus"
        date = "2026-11-08"
        reference = "PrestaShop modules/appagebuilder/logx.php"
    strings:
        $php = "<?php" nocase
        $e = /eval\s*\(\s*\$_(REQUEST|POST|GET|COOKIE|SERVER)\s*\[/ nocase
    condition:
        filesize < 2KB and $php and $e
}

rule Orphus_Linux_Miner_Watchdog_KHP
{
    meta:
        description = "Shell watchdog of a Linux miner botnet: self-copies as .X11R6/.xwd, restarts 'javad', kills rival miners"
        author = "Orphus"
        date = "2026-11-08"
        hash = "b6aa44332ccda22407ab67a2e2ab438bc5ba54463fb5f2e4eb4a6be09577dce3"
    strings:
        $s1 = "khp-wdg copy"
        $s2 = ".cache-jd"
        $s3 = "_javad_backup"
        $s4 = "JAVAD_BACKUP_DIRS"
        $s5 = "_rival_kill"
        $s6 = "_xwd_selfcopy"
        $s7 = "36362e3234352e3231372e313335"
    condition:
        filesize < 300KB and 2 of them
}

rule Orphus_IOC_C2_66_245_217_135
{
    meta:
        description = "Download host of the 'javad' miner (plain or hex-encoded)"
        author = "Orphus"
        date = "2026-11-08"
    strings:
        $ip = "66.245.217.135"
        $hex = "36362e3234352e3231372e313335"
    condition:
        any of them
}
