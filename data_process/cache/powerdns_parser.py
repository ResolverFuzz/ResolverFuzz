import os


def parse_rrset(record_str, positive_record=False):
    rr_str = record_str.split(' ; ')
    rrset = {}
    record = rr_str[0].split(' ', 5)
    rrset['name'] = record[0]
    rrset['ttl'] = record[1]
    rrset['current_ttl'] = record[2]
    rrset['class'] = record[3]
    rrset['type'] = record[4]
    rrset['rdata'] = record[5]
    rrset['rr_type'] = 'negative_record'
    if positive_record:
        rrset['rr_type'] = 'positive_record'
        record = rr_str[1].split(' ')
        if len(record) >= 4:
            rrset['source_type'] = record[0]
            rrset['auth'] = record[1].split('=')[1]
            rrset['zone'] = record[2].split('=')[1]
            rrset['from'] = record[3].split('=')[1]
    return rrset['name'], rrset


def parse_packet(packet_str):
    packet = packet_str.split(' ; ')
    rrset = {}
    record = packet[0].split(' ')
    rrset['name'] = record[0]
    rrset['ttl'] = record[1]
    rrset['type'] = record[2]
    rrset['rdata'] = record[3]
    record = packet[1].split(' ')
    rrset['rr_type'] = record[0]
    rrset['val1'] = record[1]
    rrset['val2'] = record[2]
    return rrset['name'], rrset


class PdnsCache:
    """
    Typical PowerDNS Recursors run multiple threads, therefore you’ll see duplicate, different entries for the same domains.
    The negative cache is also dumped to the same file.
    The per-thread positive and negative cache dumps are separated with an appropriate comment.
    """

    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.access(self.cache_file, os.F_OK):
            self.cache_data = self.parse_cache()

    def parse_cache(self):
        cache = {}
        status = None
        with open(self.cache_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                if line == '; main record cache dump follows':
                    status = 'positive_record'
                elif line == '; negcache dump follows':
                    status = 'negative_record'
                elif line == '; main packet cache dump from thread follows':
                    status = 'packet_cache'
                elif line == ';':
                    pass
                elif status == 'positive_record':
                    name, rrset = parse_rrset(line, positive_record=True)
                    if name in cache:
                        cache[name].append(rrset)
                    else:
                        cache[name] = [rrset]
                elif status == 'negative_record':
                    name, rrset = parse_rrset(line, positive_record=False)
                    if name in cache:
                        cache[name].append(rrset)
                    else:
                        cache[name] = [rrset]
                elif status == 'packet_cache':
                    name, rrset = parse_packet(line)
                    if name in cache:
                        cache[name].append(rrset)
                    else:
                        cache[name] = [rrset]
                else:
                    print(line)
        return cache
