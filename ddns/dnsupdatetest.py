import dns.update
import dns.query


def new_dns_record():
    ### Create A Record
    dns_domain = "%s." % domain  # Set the domain name with a trailing dot (to stop auto substitution of zone)
    update = dns.update.Update(dns_domain)  # Prepare the payload for DNS record update in the given zone/domain (dns_domain)
    update.replace(new_hostname, TTL, 'A', new_ipaddress)  # Inject the record details into the dns.update.Update class
    response = dns.query.tcp(update, PRIMARY_DNS_SERVER_IP,
                             timeout=5)  # Submit the new record to the DNS server to apply the update


domain = "networkgeeks.com"
new_ipaddress = "84.0.0.123"
new_hostname = "host1"
PRIMARY_DNS_SERVER_IP = "30.0.0.10"
TTL = "100"
new_dns_record()
