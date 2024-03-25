import os


def parse_rrset(rrset_str):
    if rrset_str[0] == ';':
        target = {'res_type': 'rrset'}
        rrset_str = rrset_str.strip('\n')
        rrset = rrset_str.split(' ')
        target['ttl'] = rrset[1]
        target['rr_count'] = rrset[2]
        target['rrsig_count'] = rrset[3]
        target['trust'] = rrset[4]
        target['security'] = rrset[5]
        target['records'] = []
        return target
    else:
        rrset = rrset_str.split('\t')
        rrset_dict = None
        if len(rrset) >= 5:
            rrset_dict = {'name': rrset[0], 'ttl': rrset[1], 'class': rrset[2], 'type': rrset[3], 'rdata': rrset[4]}
        return rrset_dict


def parse_msg(msg_str):
    if msg_str[:3] == 'msg':
        msg = {'res_type': 'msg'}
        msgset = msg_str.split(' ')
        msg['name'] = msgset[1]
        msg['class'] = msgset[2]
        msg['type'] = msgset[3]
        msg['flags'] = msgset[4]
        msg['qdcount'] = msgset[5]
        msg['ttl'] = msgset[6]
        msg['security'] = msgset[7]
        msg['an'] = msgset[8]
        msg['ns'] = msgset[9]
        msg['ar'] = msgset[10]
        msg['records'] = []
        return msg
    else:
        msg = {}
        msgset = msg_str.split(' ')
        msg['name'] = msgset[0]
        msg['class'] = msgset[1]
        msg['type'] = msgset[2]
        msg['flags'] = msgset[3]
        return msg


def convert_cache(cache):
    res = {}
    for i in cache:
        if i['records']:
            name = i['records'][0]['name']
            tmp = []
            for record in i['records']:
                tmp.append({'name': record['name'], 'ttl': record['ttl'], 'class': record['class'], 'type': record['type'],
                            'rdata': record['rdata'], 'res_type': i['res_type'], 'rr_count': i['rr_count'],
                            'rrsig_count': i['rrsig_count'], 'trust': i['trust'], 'security': i['security']})
            if name in res:
                res[name].extend(tmp)
            else:
                res[name] = tmp
    return res


class UnboundCache:
    """
    The format of the file is as follows: [RRset cache] [Message cache] EOF – fixed string "EOF" before end of the file.
    The RRset cache is: START_RRSET_CACHE [rrset]* END_RRSET_CACHE
    rrset is: ;rrset [nsec_apex] TTL rr_count rrsig_count trust security resource records, one per line, in zonefile format rrsig records, one per line, in zonefile format If the text conversion fails, BADRR is printed on the line.
    The Message cache is: START_MSG_CACHE [msg]* END_MSG_CACHE
    msg is: msg name class type flags qdcount ttl security an ns ar list of rrset references, one per line. If conversion fails, BADREF reference is: name class type flags
    Expired cache entries are not printed.
    """

    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.access(self.cache_file, os.F_OK):
            self.cache_data, self.cache_msg = self.parse_cache()

    def parse_cache(self):
        cache = []
        msg = []
        status = None
        with open(self.cache_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                if line == 'START_RRSET_CACHE':
                    status = 'RRSET_CACHE'
                elif line == 'START_MSG_CACHE':
                    status = 'MSG_CACHE'
                elif line in ['END_RRSET_CACHE', 'END_MSG_CACHE']:
                    status = None
                elif line == 'EOF':
                    break
                elif status == 'RRSET_CACHE':
                    if line[0] == ';':
                        cache.append(parse_rrset(line))
                    else:
                        tmp = parse_rrset(line)
                        if tmp:
                            cache[-1]['records'].append(tmp)
                elif status == 'MSG_CACHE':
                    if line[:3] == 'msg':
                        msg.append(parse_msg(line))
                    else:
                        msg[-1]['records'].append(parse_msg(line))
                else:
                    print(line)
        return convert_cache(cache), msg
