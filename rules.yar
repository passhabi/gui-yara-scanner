rule DemandForMoney
{
    strings:
        $demand = "pay me"
        $demand2 = "send money"
    condition:
        any of them
}


rule BlockSpecificLinks
{
    strings:
        $link1 = "example.com"
        $link2 = "malicious-site.com"
    condition:
        any of them
}


rule FileSignature
{
    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $header at 0
}


// rule DetectURLs
// {
//     strings:
//         $url = /https?:\/\/[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}/
//     condition:
//         $url
// }
