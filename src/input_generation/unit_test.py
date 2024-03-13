from scapy.layers import dns

from input_generation import dns_fuzzer


def parse_dnsrr(dnsrr):
    print(target.getDNSRR())
    print(target.makeDNSRR())
    packet = dnsrr.makeDNSRR()
    res = dns.DNSRR(packet)
    res.show()


# test for A record
print('=' * 10, 'A', '=' * 10)
target = dns_fuzzer.DNSRRA()
target_rdata = '8.8.8.8'
target.setDNSRR(rrname="google.com.", rtype=1, rclass=1, ttl=75029, rdlen=0, ipv4=target_rdata)

parse_dnsrr(target)

# test for NS record
target = dns_fuzzer.DNSRRNS()
target_rdata = "ns1.google.com."
target.setDNSRR(rrname="google.com.", rtype=2, rclass=1, ttl=75029, rdlen=0, ns=target_rdata)

parse_dnsrr(target)

# test for CNAME record
print('=' * 10, 'CNAME', '=' * 10)
target = dns_fuzzer.DNSRRCNAME()
target_rdata = "mail.google.com."
target.setDNSRR(rrname="gmail.com.", rtype=5, rclass=1, ttl=75029, rdlen=0, cname=target_rdata)

parse_dnsrr(target)

# test for DNAME record
print('=' * 10, 'DNAME', '=' * 10)
target = dns_fuzzer.DNSRRDNAME()
target_rdata = "g1.com."
target.setDNSRR(rrname="g2.com.", rtype=39, rclass=1, ttl=75029, rdlen=0, dname=target_rdata)

parse_dnsrr(target)

# test for SOA record
print('=' * 10, 'SOA', '=' * 10)
target = dns_fuzzer.DNSRRSOA()
target.setDNSRR(rrname="google.com.", rtype=6, rclass=1, ttl=21, rdlen=0, mname="ns1.google.com.",
                rname="dns-admin.google.com.", serial=472238238, refresh=900, retry=900, expire=1500, minimum=60)

parse_dnsrr(target)

# test for PTR record

target = dns_fuzzer.DNSRRPTR()
target_rdata = "lax31s19-in-f14.1e100.net."
target.setDNSRR(rrname="142.217.250.142.in-addr.arpa.", rtype=12, rclass=1, ttl=75029, rdlen=0, ptr=target_rdata)

parse_dnsrr(target)

# test for MX record
print('=' * 10, 'MX', '=' * 10)
target = dns_fuzzer.DNSRRMX()
target.setDNSRR(rrname="gmail.com.", rtype=15, rclass=1, ttl=3388, rdlen=0, preference=5,
                mx="gmail-smtp-in.l.google.com.")

parse_dnsrr(target)

# Query Generation Test
print('=' * 10, 'Query', '=' * 10)


def query_generation_test():
    df = dns_fuzzer.DNSFuzzer(public_suffix="./input_generation/public_suffix_list.dat",
                              domain_list="./input_generation/tlds-alpha-by-domain.txt",
                              top_1m="./input_generation/top-1m.csv")
    df.setRD()
    df.setAD()
    df.setQDCOUNT()
    query = df.Query()
    response = df.Response()
    return query, response

packet = query_generation_test()
query = dns.DNS(packet[0])
response = dns.DNS(packet[1])
