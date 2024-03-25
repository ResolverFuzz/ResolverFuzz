import json
import os


class TechCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.access(self.cache_file, os.F_OK):
            self.cache_data = self.parse_cache()

    def parse_cache(self):
        with open(self.cache_file, 'r') as json_file:
            cache = json.load(json_file)

        pop_list = []
        labels = list(cache.keys())
        for label in labels:
            tmp = []
            is_valid = True
            for record in cache[label]:
                if 'dataType' in record['rData'] and record['rData']['dataType'] == 'DnsSpecialCacheRecordData':
                    is_valid = False
                else:
                    if record['type'] == 'NS':
                        record['rdata'] = record['rData']['nameServer']
                    elif record['type'] == 'A':
                        record['rdata'] = record['rData']['ipAddress']
                    elif record['type'] == 'CNAME':
                        record['rdata'] = record['rData']['cname']
                    elif record['type'] == 'PTR':
                        record['rdata'] = record['rData']['ptrName']
                    elif record['type'] == 'MX':
                        record['rdata'] = record['rData']['exchange']
                    elif record['type'] == 'SOA':
                        record['rdata'] = record['rData']['primaryNameServer']
                    elif record['type'] == 'TXT':
                        record['rdata'] = record['rData']['text']
                    elif record['type'] == 'AAAA':
                        record['rdata'] = record['rData']['ipAddress']
                    elif record['type'] == 'RRSIG':
                        record['rdata'] = record['rData']['signersName']
                if is_valid:
                    tmp.append(record)
                is_valid = True
            if tmp:
                cache[label+"."] = tmp
            pop_list.append(label)
        for entry in pop_list:
            cache.pop(entry, None)
        return cache
