param (
    [string]$domain
)

if (-not $domain) {
    Write-Host "Please provide a domain name using the -domain parameter."
    exit
}

function CheckSPF {
    param ($domain)
    $txtRecords = (Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue)
    foreach ($record in $txtRecords) {
        if ($record.Strings -match "^v=spf1") {
            return $true
        }
    }
    return $false
}

function CheckDKIM {
    param ($domain)
    $selector = "default"
    $dkimDomain = "$selector._domainkey.$domain"
    $txtRecords = (Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction SilentlyContinue)
    foreach ($record in $txtRecords) {
        if ($record.Strings -match "^v=DKIM1") {
            return $true
        }
    }
    return $false
}

function CheckDMARC {
    param ($domain)
    $dmarcDomain = "_dmarc.$domain"
    $txtRecords = (Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction SilentlyContinue)
    foreach ($record in $txtRecords) {
        if ($record.Strings -match "^v=DMARC1") {
            return $true
        }
    }
    return $false
}

$baseDomain = $domain

$spf = CheckSPF $baseDomain
$dkim = CheckDKIM $baseDomain
$dmarc = CheckDMARC $baseDomain

Write-Host "SPF record found for $baseDomain: $spf"
Write-Host "DKIM record found for $baseDomain: $dkim"
Write-Host "DMARC record found for $baseDomain: $dmarc"

if (-not $spf -or -not $dkim -or -not $dmarc) {
    Write-Host "Spoofing is possible for this domain."
} else {
    Write-Host "Spoofing is unlikely for this domain."
}
