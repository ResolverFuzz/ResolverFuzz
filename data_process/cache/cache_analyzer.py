from scapy.layers.dns import DNS

from bind9_parser import Bind9Cache
from powerdns_parser import PdnsCache
from unbound_parser import UnboundCache
from technitium_parser import TechCache

ignore_domains = {'powerdns.com.', 'pdns-public-ns1.powerdns.com.',
                  'recursor-4.7.0.security-status.secpoll.powerdns.com.', 'pdns-public-ns2.powerdns.com.',
                  'secpoll.powerdns.com.', '0.security-status.secpoll.powerdns.com.',
                  '7.0.security-status.secpoll.powerdns.com.', 'security-status.secpoll.powerdns.com.', 'com.', 'net.',
                  'm.root-servers.net.', 'e.root-servers.net.', 'b.root-servers.net.', 'k.gtld-servers.net.',
                  'e.gtld-servers.net.', 'h.root-servers.net.', 'f.root-servers.net.', 'd.gtld-servers.net.',
                  'i.gtld-servers.net.', 'c.gtld-servers.net.', 'k.root-servers.net.', 'j.gtld-servers.net.',
                  'l.root-servers.net.', 'a.root-servers.net.', 'b.gtld-servers.net.', 'g.root-servers.net.',
                  'a.gtld-servers.net.', 'h.gtld-servers.net.', 'd.root-servers.net.', 'g.gtld-servers.net.',
                  'c.root-servers.net.', 'j.root-servers.net.', 'm.gtld-servers.net.', 'f.gtld-servers.net.',
                  'l.gtld-servers.net.', 'i.root-servers.net.', '.'}

ignore_domains_mode_specific = {}


# ignore_types = {'DS', 'RRSIG', 'NSEC3', 'NSEC'}
ignore_types = {}

resolver_list = {1: "bind", 2: "unbound", 3: "pdns", 4: "tech", "bind": 1, "unbound": 2, "pdns": 3, "tech": 4}


def compare(bind, unbound, pdns, tech, target):
    matrics = {}
    flag = 1
    for li in [bind, unbound, pdns, tech]:
        if li:
            for i in li:
                if i['type'] not in ignore_types:
                    if (i['type'], i['rdata']) not in matrics:
                        matrics[i['type'], i['rdata']] = flag
                    else:
                        matrics[i['type'], i['rdata']] += flag
        flag += 1

    for key, val in matrics.items():
        if val != target:
            return {"bind": bind, "unbound": unbound, "pdns": pdns, 'technitium': tech}
    return {}


def decode_query(filepath: str):
    with open(filepath, 'r') as f:
        res = f.read()

    try:
        query_packet = DNS(bytes.fromhex(res))
        return query_packet
    except:
        return None


def get_domain_list(target, domain_list, cache, path, sw_key, sw_name, debug):
    if cache:
        target += resolver_list[sw_key]
        domain_list.extend(list(cache.keys()))
    else:
        if debug:
            if cache is None:
                print("{} cache dump missing...\t".format(sw_name) + path)
                cache = {}
            else:
                print("{} cache dump empty...\t".format(sw_name) + path)
    return target, domain_list

class CacheAnalyzer:
    """
    This class is used to analyze the difference between the caches of different resolvers.
    """

    def __init__(self, directory=None, index=None, bind_path=None, unbound_path=None, pdns_path=None, tech_path=None,
                 client_query_path=None, debug=False):
        self.debug=debug
        self.res = None
        self.mode = None
        self.count = {'bind9': 0, 'powerdns': 0, 'unbound': 0, 'technitium': 0}
        if directory and index != None:
            if directory[-1] != "/":
                directory += "/"
            self.bind_path = directory + str(index) + "/bind9/named_dump.db"
            self.unbound_path = directory + str(index) + "/unbound/unbound.cache.db"
            self.pdns_path = directory + str(index) + "/powerdns/powerdns.cache.db"
            self.tech_path = directory + str(index) + "/technitium/cache.json"
            self.client_query_path = directory + str(index) + "/query.txt"
        elif bind_path and unbound_path and pdns_path and tech_path and client_query_path:
            self.bind_path = bind_path
            self.unbound_path = unbound_path
            self.pdns_path = pdns_path
            self.tech_path = tech_path
            self.client_query_path = client_query_path
        else:
            raise RuntimeError("Parameters missing...")

        self.client_query = decode_query(self.client_query_path)
        self.bind_cache = Bind9Cache(self.bind_path)
        self.pdns_cache = PdnsCache(self.pdns_path)
        self.unbound_cache = UnboundCache(self.unbound_path)
        self.tech_cache = TechCache(self.tech_path)

        self.get_difference()
        self.calc_count()

    def set_bind_path(self, bind_path):
        self.bind_path = bind_path
        self.bind_cache = Bind9Cache(self.bind_path)

    def set_pdns_path(self, pdns_path):
        self.pdns_path = pdns_path
        self.pdns_cache = PdnsCache(self.pdns_path)

    def set_unbound_path(self, unbound_path):
        self.unbound_path = unbound_path
        self.unbound_cache = UnboundCache(self.unbound_path)

    def set_tech_path(self, tech_path):
        self.tech_path = tech_path
        self.tech_cache = TechCache(self.tech_path)

    def get_difference(self):
        bind_cache = self.bind_cache.cache_data
        unbound_cache = self.unbound_cache.cache_data
        pdns_cache = self.pdns_cache.cache_data
        tech_cache = self.tech_cache.cache_data
        if bind_cache is None or unbound_cache is None or pdns_cache is None or tech_cache is None:
            self.res = None
            return


        if self.client_query:
            tmp = self.client_query.qd.fields['qname'].decode("utf-8")
            if "-fwd-fallback.qifanzhang.com." in tmp:
                self.mode = "forward_fallback"
            elif "-fwd-global.qifanzhang.com." in tmp:
                self.mode = "forward_global"
            elif "-recursive.qifanzhang.com." in tmp:
                self.mode = "recursive"
            elif ".qifanzhang.com." in tmp:
                self.mode = "forward_only"
            else:
                self.mode = "alexa_domain"

        target = 0
        domain_list = []
        target, domain_list = get_domain_list(target, domain_list, bind_cache, self.bind_path, 'bind', 'Bind9', self.debug)
        target, domain_list = get_domain_list(target, domain_list, unbound_cache, self.unbound_path, 'unbound', 'Unbound', self.debug)
        target, domain_list = get_domain_list(target, domain_list, pdns_cache, self.pdns_path, 'pdns', 'PowerDNS', self.debug)
        target, domain_list = get_domain_list(target, domain_list, tech_cache, self.tech_path, 'tech', 'Technitium', self.debug)

        # if bind_cache:
        #     target += resolver_list['bind']
        #     domain_list.extend(list(bind_cache.keys()))
        # else:
        #     if self.debug:
        #         if bind_cache is None:
        #             print("Bind9 cache dump missing...\t" + self.bind_path)
        #             bind_cache = {}
        #         else:
        #             print("Bind9 cache dump empty...\t" + self.bind_path)
        # if unbound_cache:
        #     target += resolver_list['unbound']
        #     domain_list.extend(list(unbound_cache.keys()))
        # else:
        #     if self.debug:
        #         if unbound_cache is None:
        #             print("Unbound cache dump missing...\t" + self.unbound_path)
        #             unbound_cache = {}
        #         else:
        #             print("Unbound cache dump empty...\t" + self.unbound_path)
        # if pdns_cache:
        #     target += resolver_list['pdns']
        #     domain_list.extend(list(pdns_cache.keys()))
        # else:
        #     if self.debug:
        #         if pdns_cache is None:
        #             print("PowerDNS cache dump missing...\t" + self.pdns_path)
        #             pdns_cache = {}
        #         else:
        #             print("PowerDNS cache dump empty...\t" + self.pdns_path)
        # if tech_cache:
        #     target += resolver_list['tech']
        #     domain_list.extend(list(tech_cache.keys()))
        # else:
        #     if self.debug:
        #         if tech_cache is None:
        #             print("Technitium cache dump missing...\t" + self.tech_path)
        #             tech_cache = {}
        #         else:
        #             print("Technitium cache dump empty...\t" + self.tech_path)

        domain_list = list(set(domain_list))

        res = {}
        ignore_list = ignore_domains.union(ignore_domains_mode_specific.get(self.mode, {}))
        for domain in domain_list:
            if domain not in ignore_list:
                if (bind_cache and domain not in bind_cache) or (unbound_cache and domain not in unbound_cache) or (
                        pdns_cache and domain not in pdns_cache) or (tech_cache and domain not in tech_cache):
                    cache = []
                    diff = False
                    if domain in bind_cache:
                        cache.append(bind_cache)
                    if domain in unbound_cache:
                        cache.append(unbound_cache)
                    if domain in pdns_cache:
                        cache.append(pdns_cache)
                    if domain in tech_cache:
                        cache.append(tech_cache)
                    for i in cache:
                        for record in i.get(domain):
                            if record['type'] not in ignore_types:
                                diff = True
                    if diff:
                        res[domain] = {"bind": bind_cache.get(domain), "unbound": unbound_cache.get(domain),
                                       "pdns": pdns_cache.get(domain), "technitium": tech_cache.get(domain)}
                else:
                    tmp = compare(bind_cache.get(domain), unbound_cache.get(domain), pdns_cache.get(domain), tech_cache.get(domain), target)
                    if tmp:
                        res[domain] = tmp
        self.res = res

    def set_count(self):
        self.count = {'bind9': 0, 'powerdns': 0, 'unbound': 0, 'technitium': 0}
        if self.res is not None:
            for domain in self.res:
                record = self.res[domain]
                if record['bind']:
                    self.count['bind9'] += 1
                if record['unbound']:
                    self.count['unbound'] += 1
                if record['pdns']:
                    self.count['powerdns'] += 1
                if record['technitium']:
                    self.count['technitium'] += 1

    def get_count(self):
        return [self.count['bind9'], self.count['unbound'], self.count['powerdns'], self.count['technitium']]

    def calc_count(self):
        self.set_count()
        return self.get_count()
