import os


def parse_soa(record_str):
    tmp = record_str.split(" ", 3)
    rrset = {'name': tmp[1], 'type': tmp[2], 'rdata': tmp[3]}
    return rrset['name'], rrset


def parse_rrset(record_str, domain_name, source_type, view):
    rrset = {'source_type': source_type, 'view': view}
    record = record_str.split('\t')
    if len(record) < 3:
        record = record_str.split(' ')
    if domain_name:
        rrset['name'] = domain_name
    else:
        rrset['name'] = record[0]
    if record[-2][:3] == 'IN ':
        rrset['type'] = record[-2][3:]
        rrset['ttl'] = record[-3]
    else:
        rrset['type'] = record[-2]
        if record[-3] == 'IN':
            rrset['ttl'] = record[-4]
        else:
            rrset['ttl'] = record[-3]
    rrset['rdata'] = record[-1]
    return rrset['name'], rrset


class Bind9Cache:
    """
    Cache Extraction for Bind9
    """

    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.access(self.cache_file, os.F_OK):
            self.cache_data, self.config = self.parse_cache()

    def parse_cache(self):
        cache = {}
        view = None
        status = None
        source_type = None
        config = {}
        domain = ""
        with open(self.cache_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                if line == ';':
                    pass
                elif line[:12] == '; Start view':
                    view = line[13:]
                    config[view] = {}
                elif line[:12] == '; Cache dump':
                    status = 'cache'
                elif line[:23] == '; Address database dump':
                    status = 'address'
                elif line[:22] == '; Unassociated entries':
                    status = 'unassociated'
                elif line[:11] == '; Bad cache':
                    status = 'bad_cache'
                elif line[:16] == '; SERVFAIL cache':
                    status = 'servfail_cache'
                elif line[:9] == '; using a':
                    tmp = line.split()
                    config[view]['stale_ttl'] = tmp[3]
                elif line[:15] == '; Dump complete':
                    break
                elif line[:5] == '$DATE':
                    tmp = line.split()
                    config[view]['date'] = tmp[1]
                elif line[0] == ';':
                    tmp = line.split(' ', 3)
                    if len(tmp) < 3:
                        source_type = tmp[1]
                    else:
                        if status == 'cache':
                            name, soa = parse_soa(line)
                            if name in cache:
                                cache[name].append(soa)
                            else:
                                cache[name] = [soa]
                elif status == 'cache':
                    if line[:5] == '\t\t\t\t\t':
                        cache[domain][-1]['rdata'] = cache[domain][-1]['rdata'] + line[5:]
                    else:
                        if line[0] == '\t':
                            name, rrset = parse_rrset(line, domain_name=domain, source_type=source_type, view=view)
                        else:
                            name, rrset = parse_rrset(line, domain_name=None, source_type=source_type, view=view)
                            domain = name
                        if name in cache:
                            cache[name].append(rrset)
                        else:
                            cache[name] = [rrset]
                else:
                    print(line)
        return cache, config
