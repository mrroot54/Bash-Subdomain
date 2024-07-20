#!/bin/bash

help(){
    echo -e "[Usage]:"
    echo -e "\t$ ~/subdomain.sh DOMAIN"
}

getSubdomains(){
    domain=$1
    mkdir -p "$domain" # Create a folder with the domain name
    
    # Perform subdomain enumeration using various services
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r ".passive_dns[].hostname" | sort -u > "$domain/tmp.txt" &
    curl -s "https://jldc.me/anubis/subdomains/$domain" | jq -r '.' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> "$domain/tmp.txt" &
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u >> "$domain/tmp.txt" &
    curl -s "https://certspotter.com/api/v0/certs?domain=$domain" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w "$domain"\$ | sort -u >> "$domain/tmp.txt" &
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$domain/tmp.txt" &
    curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u >> "$domain/tmp.txt" &
    curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u >> "$domain/tmp.txt" &
    curl -s "https://tls.bufferover.run/dns?q=.$domain" | jq -r .Results 2>/dev/null | cut -d ',' -f3 | grep -o "\w.*$domain" | sort -u >> "$domain/tmp.txt" &
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | cut -d ',' -f1 | sort -u >> "$domain/tmp.txt" &
    curl -s "https://rapiddns.io/subdomain/$domain?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep "$domain" | sed 's/https\?:\/\///' | cut -d "/" -f3 | sort -u >> "$domain/tmp.txt" &
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -o "\w.*$domain" | cut -d ',' -f6 | sort -u >> "$domain/tmp.txt" &
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq '.subdomains' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> "$domain/tmp.txt" &
    curl -s "https://api.threatminer.org/v2/domain.php?q=$domain&rt=5" | jq -r '.results[]' | sort -u >> "$domain/tmp.txt" &
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" | jq -r '.results[].page.domain' | sort -u >> "$domain/tmp.txt" &
    curl -s "https://www.virustotal.com/ui/domains/$domain/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> "$domain/tmp.txt" &

    # Extract subdomains from dnsdumpster.com
    csrftoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
    curl -s --header "Host: dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$csrftoken&targetip=$domain" --cookie "csrftoken=$csrftoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com >> "$domain/dnsdumpster.html"
    if [[ -e "$domain/dnsdumpster.html" && -s "$domain/dnsdumpster.html" ]]; then # File exists and is not zero size
        cat "$domain/dnsdumpster.html" | grep "https://api.hackertarget.com/httpheaders" | grep -o "\w.*$domain" | cut -d "/" -f7 | grep '.' | sort -u >> "$domain/tmp.txt"
    fi

    # Consolidate and clean up the subdomain list
    cat "$domain/tmp.txt" | grep -iv "*" | sort -u | grep "$domain" > "$domain/subdomains.txt"
    rm -rf "$domain/dnsdumpster.html"
    rm -rf "$domain/tmp.txt"
    
    # Check which subdomains are alive and save to alive-subdomains.txt
    cat "$domain/subdomains.txt" | httpx -title -wc -sc -cl -ct -location -web-server -asn -o "$domain/alive-subdomains.txt"
}

if [[ -z $1 ]]; then
    help
else
    getSubdomains $1
fi
