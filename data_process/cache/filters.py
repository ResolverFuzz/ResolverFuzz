from scapy import all as scapy

def collect_info(caches):
    count = {'bind9': 0, 'pdns': 0, 'technitium': 0, 'unbound': 0}
    for cache in caches:
        if cache.count['bind9'] > 0:
            count['bind9'] += 1
        if cache.count['powerdns'] > 0:
            count['pdns'] += 1
        if cache.count['unbound'] > 0:
            count['unbound'] += 1
        if cache.count['technitium'] > 0:
            count['technitium'] += 1
    return count, len(caches)

def filter_cp1(caches):
    sw_list = ['bind', 'technitium']
    count = 0
    ignore_domain = ['merlin.ns.cloudflare.com.', 'stephane.ns.cloudflare.com.', 'qifanzhang.com.', 'ns.cloudflare.com.', 'cloudflare.com.', 'gtld-servers.net.', 'CK0POJMG874LJREF7EFN8430QVIT8BSM.com.', '3RL2Q58205687C8I9KC9MV46DGHCNS45.com.', 'nstld.com.', 'av4.nstld.com.', 'av2.nstld.com.', 'av1.nstld.com.', 'av3.nstld.com.', 'G1DHAQQ6L74TAIA763K3US9DMVGSGPP2.com.', 'j.root-servers.', 'nia.ns.cloudflare.com.', 'chad.ns.cloudflare.com.']
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            if ".xuesongb.com." not in ind and ind not in ignore_domain:
                for sw in sw_list:
                    if record[sw]:
                        for i in record[sw]:
                            print(ind + '\t' + i['type'] + '\t' + str(caches.index(cache)) + '\t' + str(i['rdata']))
                            flag = True
        if flag:
            count += 1
    return count

def filter_cp2(caches):
    sw_list = ['pdns']
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if cache.client_query.qd.fields['qname'].decode("utf-8") in ind and cache.client_query.qd.fields['qname'].decode("utf-8") != ind and i['type'] == 'NS':
                            print(cache.client_query.qd.fields['qname'].decode("utf-8"), ind)
                            flag = True
        if flag:
            count += 1
    return count

def filter_cp4(caches):
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if cache.client_query.qd.fields['qname'].decode("utf-8") in ind and cache.client_query.qd.fields['qname'].decode("utf-8") != ind and i['type'] == 'NS':
                            print(cache.client_query.qd.fields['qname'].decode("utf-8"), ind)
                            flag = True
        if flag:
            count += 1
    return count

def filter_r1(caches):
    # Cache record for target domain and type
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        tmp = cache.client_query.getlayer(scapy.DNSQR)
        qtype = tmp.get_field('qtype').i2repr(tmp, tmp.qtype)
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if cache.client_query.qd.fields['qname'].decode("utf-8") == ind and i['type'] == qtype:
                            flag = True
        if flag:
            count += 1
    return count

def filter_r2(caches):
    # Fall back for Bind9 and Unbound
    sw_list = ['bind', 'unbound']
    count = 0
    target_domain = {'merlin.ns.cloudflare.com.', 'stephane.ns.cloudflare.com.', 'nia.ns.cloudflare.com.', 'chad.ns.cloudflare.com.'}
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            if ind in target_domain:
                for sw in sw_list:
                    if record[sw]:
                        for i in record[sw]:
                            # print(ind + '\t' + i['type'] + '\t' + str(caches.index(cache)))
                            flag = True
        if flag:
            count += 1
    return count

def filter_r3(caches):
    # Cache NSEC3  record
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    type_list = {'NSEC3'}
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if i['type'] in type_list:
                            flag = True
        if flag:
            count += 1
    return count

def filter_r4(caches):
    # Cache NSEC record
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    type_list = {'NSEC'}
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if i['type'] in type_list:
                            flag = True
        if flag:
            count += 1
    return count

def filter_r5(caches):
    # Cache NSEC3 or NSEC record
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    type_list = {'NSEC', 'NSEC3'}
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if i['type'] in type_list:
                            flag = True
        if flag:
            count += 1
    return count

def filter_r6(caches):
    # Cache record for target domain different type
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    count = 0
    for cache in caches:
        flag = False
        target = cache.res
        tmp = cache.client_query.getlayer(scapy.DNSQR)
        qtype = tmp.get_field('qtype').i2repr(tmp, tmp.qtype)
        for ind in target:
            record = target[ind]
            for sw in sw_list:
                if record[sw]:
                    for i in record[sw]:
                        if cache.client_query.qd.fields['qname'].decode("utf-8") == ind and i['type'] != qtype:
                            flag = True
        if flag:
            count += 1
    return count

def filter_r7(caches):
    # Revalidation
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    count = 0
    target_domain = {'cloudflare.com.'}
    for cache in caches:
        flag = False
        target = cache.res
        for ind in target:
            record = target[ind]
            if ind in target_domain:
                for sw in sw_list:
                    if record[sw]:
                        for i in record[sw]:
                            # print(ind + '\t' + i['type'] + '\t' + str(caches.index(cache)))
                            flag = True
        if flag:
            count += 1
    return count

target = cluster_res[4]
count, total = collect_info(target)
print("CP1")
cp1 = filter_cp1(target)
print("CP2")
cp2 = filter_cp2(target)
print("CP4")
cp4 = filter_cp4(target)
print("R1")
r1 = filter_r1(target)
print("R2")
r2 = filter_r2(target)
print("R3")
r3 = filter_r3(target)
print("R4")
r4 = filter_r4(target)
print("R5")
r5 = filter_r5(target)
print("R6")
r6 = filter_r6(target)
print("R7")
r7 = filter_r7(target)
print("Total: \t" + str(total))
print(count)
print("CP1: \t" + str(cp1))
print("CP2: \t" + str(cp2))
print("CP4: \t" + str(cp4))
print("R1: \t" + str(r1))
print("R2: \t" + str(r2))
print("R3: \t" + str(r3))
print("R4: \t" + str(r4))
print("R5: \t" + str(r5))
print("R6: \t" + str(r6))
print("R7: \t" + str(r7))

for i in range(6):
    target = cluster_res[i]
    count, total = collect_info(target)
    print("Total: \t" + str(total))
    # cp1 = filter_cp1(target)
    # cp2 = filter_cp2(target)
    # cp4 = filter_cp4(target)
    r2 = filter_r2(target)
    print("R2: \t" + str(r2))
    # r3 = filter_r3(target)
    # print("R3: \t" + str(r3))
    r4 = filter_r4(target)
    # print("R4: \t" + str(r4))
