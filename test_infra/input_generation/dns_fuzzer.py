#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   dns_fuzzer.py
@Contact :   
@License :   (C)Copyright 2022

@Modify Time        @Author     @Version    @Description
----------------    --------    --------    -----------
30/6/2022 12:54     idealeer    0.0         None
"""
import ipaddress
import json
import random
import socket
import string
from enum import Enum
from typing import List

domain_forward_only = "test0-fwd-only.qifanzhang.com."
domain_forward_fallback = "test0-fwd-fallback.qifanzhang.com."
domain_recursive = "test0-recursive.qifanzhang.com."

# DNS header flag bit position
DNSHeaderFlagBitPosition = {
	"QR": 7,
	"OPCODE": 3,
	"AA": 2,
	"TC": 1,
	"RD": 0,
	"RA": 7,
	"Z": 6,
	"AD": 5,
	"CD": 4,
	"RCODE": 0,
}

# DNS field value upper bound
DNSFieldMaxValue = {
	"TXID": 2 ** 16 - 1,
	"QR": 2 ** 1 - 1,
	"OPCODE": 2 ** 4 - 1,
	"AA": 2 ** 1 - 1,
	"TC": 2 ** 1 - 1,
	"RD": 2 ** 1 - 1,
	"RA": 2 ** 1 - 1,
	"Z": 2 ** 1 - 1,
	"AD": 2 ** 1 - 1,
	"CD": 2 ** 1 - 1,
	"RCODE": 2 ** 4 - 1,
	"QDCOUNT": 2 ** 4 - 1,
	"ANCOUNT": 2 ** 4 - 1,
	"NSCOUNT": 2 ** 4 - 1,
	"ARCOUNT": 2 ** 4 - 1,
	"NAMELEN": 256 - 1,
	"LABELLEN": 64 - 1,
	"LABELNUM": 128 - 1,
	"TYPE": 2 ** 16 - 1,
	"CLASS": 2 ** 16 - 1,
	"TTL": 2 ** 32 - 1,
	"RDLEN": 2 * 16 - 1,
}


# Generate bytes stream
def bytesField(inp, bytesCount):
	return inp.to_bytes(bytesCount, byteorder="big")


# Generate one byte stream
def oneByteField(inp):
	return bytesField(inp, 1)


# Generate two bytes stream
def twoBytesField(inp):
	return bytesField(inp, 2)


# Generate four bytes stream
def fourBytesField(inp):
	return bytesField(inp, 4)


# Generate DNS name byte stream
# Input must ends with '.', like "google.com."
def makeDNSName(name):
	name = name.rstrip(".") + "."
	res = ""
	labels = name.split(".")
	for ele in labels:
		res += chr(len(ele)) + ele
	return res.encode()


# Generate IPv4 byte stream
# Format: a.b.c.d
def makeIP4(ip4_str):
	return bytes([int(ele) for ele in ip4_str.split(".")])


# Base enum class
class ExtendedEnum(Enum):

	@classmethod
	def nameList(cls):
		return list(map(lambda m: m.name, cls))

	@classmethod
	def valueList(cls):
		return list(map(lambda m: m.value, cls))


# DNS classes
class DNSClasses(ExtendedEnum):
	IN = 1
	CH = 3
	HS = 4
	NONE = 254
	ANY = 255


# DNS classes
class DNSClassesCommon(ExtendedEnum):
	IN = 1


# DNS types
class DNSTypes(ExtendedEnum):
	A = 1
	NS = 2
	MD = 3
	MF = 4
	CNAME = 5
	SOA = 6
	MB = 7
	MG = 8
	MR = 9
	NULL = 10
	WKS = 11
	PTR = 12
	HINFO = 13
	MINFO = 14
	MX = 15
	TXT = 16
	RP = 17
	AFSDB = 18
	X25 = 19
	ISDN = 20
	RT = 21
	NSAP = 22
	NSAPPTR = 23
	SIG = 24
	KEY = 25
	PX = 26
	GPOS = 27
	AAAA = 28
	LOC = 29
	NXT = 30
	EID = 31
	NIMLOC = 32
	SRV = 33
	ATMA = 34
	NAPTR = 35
	KX = 36
	CERT = 37
	A6 = 38
	DNAME = 39
	SINK = 40
	OPT = 41
	APL = 42
	DS = 43
	SSHFP = 44
	IPSECKEY = 45
	RRSIG = 46
	NSEC = 47
	DNSKEY = 48
	DHCID = 49
	NSEC3 = 50
	NSEC3PARAM = 51
	TLSA = 52
	SMIMEA = 53
	HIP = 55
	NINFO = 56
	RKEY = 57
	TALINK = 58
	CDS = 59
	CDNSKEY = 60
	OPENPGPKEY = 61
	CSYNC = 62
	ZONEMD = 63
	SVCB = 64
	HTTPS = 65
	SPF = 99
	UINFO = 100
	UID = 101
	GID = 102
	UNSPEC = 103
	NID = 104
	L32 = 105
	L64 = 106
	LP = 107
	EUI48 = 108
	EUI64 = 109
	TKEY = 249
	TSIG = 250
	IXFR = 251
	AXFR = 252
	MAILB = 253
	MAILA = 254
	ANY = 255
	URI = 256
	CAA = 257
	AVC = 258
	DOA = 259
	AMTRELAY = 260
	TA = 32768
	DLV = 32769


# DNS types
class DNSTypesCommon(ExtendedEnum):
	A = 1
	NS = 2
	CNAME = 5
	SOA = 6
	PTR = 12
	MX = 15
	TXT = 16
	AAAA = 28
	RRSIG = 46
	SPF = 99
	ANY = 255


# DNS types
class DNSTypesCommonNoANY(ExtendedEnum):
	A = 1
	NS = 2
	CNAME = 5
	SOA = 6
	PTR = 12
	MX = 15
	TXT = 16
	AAAA = 28
	RRSIG = 46
	SPF = 99


# DNS operation codes
class DNSOpCodes(ExtendedEnum):
	QUERY = 0
	IQUERY = 1
	STATUS = 2
	NOTIFY = 4
	UPDATE = 5
	DSO = 6


# DNS operation codes
class DNSOpCodesCommon(ExtendedEnum):
	QUERY = 0


# DNS return codes
class DNSRCodes(ExtendedEnum):
	NOERROR = 0
	FORMERR = 1
	SERVFAIL = 2
	NXDOMAIN = 3
	NOTIMP = 4
	REFUSED = 5
	YXDOMAIN = 6
	YXRRSET = 7
	NXRRSET = 8
	NOTAUTH = 9
	NOTZONE = 10
	DSOTYPENI = 11
	BADVERS = 16
	BADSIG = 16
	BADKEY = 17
	BADTIME = 18
	BADMODE = 19
	BADNAME = 20
	BADALG = 21
	BADTRUNC = 22
	BADCOOKIE = 23


# DNS return codes
class DNSRCodesCommon(ExtendedEnum):
	NOERROR = 0


# DNSSEC algorithm numbers
class DNSSECAlgNums(ExtendedEnum):
	DELETE = 0
	RSAMD5 = 1
	DH = 2
	DSA = 3
	RSASHA1 = 5
	DSA_NSEC3_SHA1 = 6
	RSASHA1_NSEC3_SHA1 = 7
	RSASHA256 = 8
	RSASHA512 = 10
	ECC_GOST = 12
	ECDSAP256SHA256 = 13
	ECDSAP384SHA384 = 14
	ED25519 = 15
	ED448 = 16
	INDIRECT = 252
	PRIVATEDNS = 253
	PRIVATEOID = 254


# DNS question record
class DNSQR:
	"""DNS Question Record"""

	def __init__(self):
		self.QNAME_STR = ""
		self.QNAME_HEX = "".encode().hex()
		self.QNAME = "".encode()
		self.QTYPE = 0
		self.QTYPE_STR = ""
		self.QCLASS = 0
		self.QCLASS_STR = ""

	def setDNSQR(self, qname="", qtype=0, qclass=0):
		self.QNAME_STR = qname
		self.QNAME_HEX = qname.encode().hex()
		self.QNAME = makeDNSName(qname)
		self.QTYPE = qtype & (DNSFieldMaxValue["TYPE"])
		self.QTYPE_STR = DNSTypes(self.QTYPE).name
		self.QCLASS = qclass & (DNSFieldMaxValue["CLASS"])
		self.QCLASS_STR = DNSClasses(self.QCLASS).name

	def unsetDNSQR(self):
		self.QNAME_STR = ""
		self.QNAME_HEX = "".encode().hex()
		self.QNAME = "".encode()
		self.QTYPE = 0
		self.QTYPE_STR = ""
		self.QCLASS = 0
		self.QCLASS_STR = ""

	def getDNSQR(self):
		return {"QNAME": self.QNAME_HEX, "QNAME_STR": self.QNAME_STR,
				"QTYPE": self.QTYPE, "QTYPE_STR": self.QTYPE_STR,
				"QCLASS": self.QCLASS, "QCLASS_STR": self.QCLASS_STR}

	def makeDNSQR(self):
		return self.QNAME + twoBytesField(self.QTYPE) + twoBytesField(self.QCLASS)


# DNS resource record
class DNSRR:
	"""DNS Resource Record"""

	def __init__(self):
		self.RRNAME_STR = ""
		self.RRNAME_HEX = "".encode().hex()
		self.RRNAME = "".encode()
		self.RTYPE = 0
		self.RTYPE_STR = ""
		self.RCLASS = 0
		self.RCLASS_STR = ""
		self.TTL = 0
		self.RDLEN = 0
		self.RDATA = "".encode()
		self.RDATA_HEX = "".encode().hex()
		self.RDATA_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0):
		self.RRNAME_STR = rrname
		self.RRNAME_HEX = rrname.encode().hex()
		self.RRNAME = makeDNSName(rrname)
		self.RTYPE = rtype
		self.RTYPE_STR = DNSTypes(self.RTYPE).name
		self.RCLASS = rclass
		self.RCLASS_STR = DNSClasses(self.RCLASS).name
		self.TTL = ttl

	def unsetDNSRR(self):
		self.RRNAME_STR = ""
		self.RRNAME_HEX = "".encode().hex()
		self.RRNAME = "".encode()
		self.RTYPE = 0
		self.RTYPE_STR = ""
		self.RCLASS = 0
		self.RCLASS_STR = ""
		self.TTL = 0
		self.RDLEN = 0
		self.RDATA = "".encode()
		self.RDATA_HEX = "".encode().hex()
		self.RDATA_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR, "RTYPE": self.RTYPE,
				"RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR, "TTL": self.TTL,
				"RDLEN": self.RDLEN, "RDATA": self.RDATA_HEX, "RDATA_STR": self.RDATA_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.RDATA


# DNS resource record Type NAME
class DNSRRNAME(DNSRR):
	"""DNS Resource Record Type NAME"""

	def __init__(self):
		super().__init__()

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, rdata=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.RDATA_STR = rdata
		self.RDATA_HEX = rdata.encode().hex()
		self.RDATA = makeDNSName(rdata)
		self.RDLEN = len(self.RDATA)

	def unsetDNSRR(self):
		super().unsetDNSRR()

	def getDNSRR(self):
		return super().getDNSRR()

	def makeDNSRR(self):
		return super().makeDNSRR()


# DNS resource record Type DATA
class DNSRRDATA(DNSRR):
	"""DNS Resource Record Type DATA"""

	def __init__(self):
		super().__init__()

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, rdata=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.RDATA_STR = rdata
		self.RDATA_HEX = rdata.encode().hex()
		self.RDATA = rdata.encode()
		self.RDLEN = len(self.RDATA)

	def unsetDNSRR(self):
		super().unsetDNSRR()

	def getDNSRR(self):
		return super().getDNSRR()

	def makeDNSRR(self):
		return super().makeDNSRR()


# DNS resource record Type A
class DNSRRA(DNSRR):
	"""DNS Resource Record Type A"""

	def __init__(self):
		super().__init__()

		self.IPv4 = "".encode()
		self.IPv4_HEX = "".encode().hex()
		self.IPv4_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, ipv4=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.IPv4_STR = ipv4
		self.IPv4_HEX = ipv4.encode().hex()
		self.IPv4 = makeIP4(ipv4)
		self.RDLEN = 4

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.IPv4 = "".encode()
		self.IPv4_HEX = "".encode().hex()
		self.IPv4_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR, "RTYPE": self.RTYPE,
				"RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR, "TTL": self.TTL,
				"RDLEN": self.RDLEN, "IPv4": self.IPv4_HEX, "IPv4_STR": self.IPv4_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.IPv4


# DNS resource record Type NS
class DNSRRNS(DNSRR):
	"""DNS Resource Record Type NS"""

	def __init__(self):
		super().__init__()

		self.NS = "".encode()
		self.NS_HEX = "".encode().hex()
		self.NS_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, ns=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.NS_STR = ns
		self.NS_HEX = ns.encode().hex()
		self.NS = makeDNSName(ns)
		self.RDLEN = len(self.NS)

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.NS = "".encode()
		self.NS_HEX = "".encode().hex()
		self.NS_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR, "RTYPE": self.RTYPE,
				"RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR, "TTL": self.TTL,
				"RDLEN": self.RDLEN, "NS": self.NS_HEX, "NS_STR": self.NS_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.NS


# DNS resource record Type CNAME
class DNSRRCNAME(DNSRR):
	"""DNS Resource Record Type CNAME"""

	def __init__(self):
		super().__init__()

		self.CNAME = "".encode()
		self.CNAME_HEX = "".encode().hex()
		self.CNAME_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, cname=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.CNAME_STR = cname
		self.CNAME_HEX = cname.encode().hex()
		self.CNAME = makeDNSName(cname)
		self.RDLEN = len(self.CNAME)

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.CNAME = "".encode()
		self.CNAME_HEX = "".encode().hex()
		self.CNAME_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR, "RTYPE": self.RTYPE,
				"RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR, "TTL": self.TTL,
				"RDLEN": self.RDLEN, "CNAME": self.CNAME_HEX, "CNAME_STR": self.CNAME_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.CNAME


# DNS resource record Type DNAME
class DNSRRDNAME(DNSRR):
	"""DNS Resource Record Type DNAME"""

	def __init__(self):
		super().__init__()

		self.DNAME = "".encode()
		self.DNAME_HEX = "".encode().hex()
		self.DNAME_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, dname=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.DNAME_STR = dname
		self.DNAME_HEX = dname.encode().hex()
		self.DNAME = makeDNSName(dname)
		self.RDLEN = len(self.DNAME)

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.DNAME = "".encode()
		self.DNAME_HEX = "".encode().hex()
		self.DNAME_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR, "RTYPE": self.RTYPE,
				"RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR, "TTL": self.TTL,
				"RDLEN": self.RDLEN, "DNAME": self.DNAME_HEX, "DNAME_STR": self.DNAME_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.DNAME


# DNS resource record SOA
class DNSRRSOA(DNSRR):
	"""DNS Resource Record SOA"""

	def __init__(self):
		super().__init__()

		self.MNAME_STR = ""
		self.MNAME_HEX = "".encode().hex()
		self.MNAME = "".encode()
		self.RNAME_STR = ""
		self.RNAME_HEX = "".encode().hex()
		self.RNAME = "".encode()
		self.SERIAL = 0
		self.REFRESH = 0
		self.RETRY = 0
		self.EXPIRE = 0
		self.MINIMUM = 0

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, mname="", rname="", serial=0, refresh=0, retry=0,
				 expire=0, minimum=0):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.MNAME_STR = mname
		self.MNAME_HEX = mname.encode().hex()
		self.MNAME = makeDNSName(mname)
		self.RNAME_STR = rname
		self.RNAME_HEX = rname.encode().hex()
		self.RNAME = makeDNSName(rname)
		self.SERIAL = serial
		self.REFRESH = refresh
		self.RETRY = retry
		self.EXPIRE = expire
		self.MINIMUM = minimum
		self.RDLEN = len(self.MNAME) + len(self.RNAME) + 20

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.MNAME_STR = ""
		self.MNAME_HEX = "".encode().hex()
		self.MNAME = "".encode()
		self.RNAME_STR = ""
		self.RNAME_HEX = "".encode().hex()
		self.RNAME = "".encode()
		self.SERIAL = 0
		self.REFRESH = 0
		self.RETRY = 0
		self.EXPIRE = 0
		self.MINIMUM = 0

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR,
				"RTYPE": self.RTYPE, "RTYPE_STR": self.RTYPE_STR,
				"RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR,
				"TTL": self.TTL, "RDLEN": self.RDLEN,
				"MNAME": self.MNAME_HEX, "MNAME_STR": self.MNAME_STR,
				"RNAME": self.RNAME_HEX, "RNAME_STR": self.RNAME_STR,
				"SERIAL": self.SERIAL, "REFRESH": self.REFRESH, "RETRY": self.RETRY,
				"EXPIRE": self.EXPIRE, "MINIMUM": self.MINIMUM}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + self.MNAME + self.RNAME + fourBytesField(
			self.SERIAL) + fourBytesField(self.REFRESH) + fourBytesField(self.RETRY) + fourBytesField(
			self.EXPIRE) + fourBytesField(self.MINIMUM)


# DNS resource record Type PTR
class DNSRRPTR(DNSRRNAME):
	"""DNS Resource Record Type PTR"""

	def __init__(self):
		super().__init__()

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, ptr=""):
		super().setDNSRR(rrname, rtype, rclass, ttl, rdlen, ptr)

	def unsetDNSRR(self):
		super().unsetDNSRR()

	def getDNSRR(self):
		return super().getDNSRR()

	def makeDNSRR(self):
		return super().makeDNSRR()


# DNS resource record Type MX
class DNSRRMX(DNSRR):
	"""DNS Resource Record Type MX"""

	def __init__(self):
		super().__init__()

		self.PREFERENCE = 0
		self.MX_STR = ""
		self.MX_HEX = "".encode().hex()
		self.MX = "".encode()

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, preference=0, mx=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.PREFERENCE = preference
		self.MX_STR = mx
		self.MX_HEX = mx.encode().hex()
		self.MX = makeDNSName(mx)
		self.RDLEN = 2 + len(self.MX)

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.PREFERENCE = 0
		self.MX_STR = ""
		self.MX_HEX = "".encode().hex()
		self.MX = "".encode()

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR,
				"RTYPE": self.RTYPE, "RTYPE_STR": self.RTYPE_STR,
				"RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR,
				"TTL": self.TTL, "RDLEN": self.RDLEN, "PREFERENCE": self.PREFERENCE,
				"MX": self.MX_HEX, "MX_STR": self.MX_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + twoBytesField(self.PREFERENCE) + self.MX


# DNS resource record Type TXT
class DNSRRTXT(DNSRR):
	"""DNS Resource Record Type TXT"""

	def __init__(self):
		super().__init__()

		self.TXTLEN = 0
		self.TXT = "".encode()
		self.TXT_HEX = "".encode().hex()
		self.TXT_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, txt=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.TXT_STR = txt
		self.TXT_HEX = txt.encode().hex()
		self.TXT = txt.encode()
		self.TXTLEN = len(txt)
		self.RDLEN = self.TXTLEN + 1

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.TXTLEN = 0
		self.TXT = "".encode()
		self.TXT_HEX = "".encode().hex()
		self.TXT_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR,
				"RTYPE": self.RTYPE, "RTYPE_STR": self.RTYPE_STR,
				"RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR,
				"TTL": self.TTL, "RDLEN": self.RDLEN, "TXTLEN": self.TXTLEN,
				"TXT": self.TXT_HEX, "TXT_STR": self.TXT_STR}

	def makeDNSRR(self):
		print(self.TXTLEN)
		if self.TXTLEN > 255:
			self.TXTLEN = 255
			self.TXT = self.TXT[:self.TXTLEN]
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + oneByteField(self.TXTLEN) + self.TXT


# DNS resource record Type AAAA
class DNSRRAAAA(DNSRR):
	"""DNS Resource Record Type AAAA"""

	def __init__(self):
		super().__init__()

		self.IPv6 = "".encode()
		self.IPv6_HEX = "".encode().hex()
		self.IPv6_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, ipv6=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.IPv6_STR = ipv6
		self.IPv6_HEX = ipv6.encode().hex()
		self.IPv6 = ipaddress.IPv6Address(ipv6).packed
		self.RDLEN = 16

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.IPv6 = "".encode()
		self.IPv6_HEX = "".encode().hex()
		self.IPv6_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR,
				"RTYPE": self.RTYPE, "RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR,
				"TTL": self.TTL, "RDLEN": self.RDLEN, "IPv6": self.IPv6_HEX, "IPv6_STR": self.IPv6_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(self.TTL) + \
			   twoBytesField(self.RDLEN) + self.IPv6


# DNS resource record Type RRSIG
class DNSRRRRSIG(DNSRR):
	"""DNS Resource Record Type RRSIG"""

	def __init__(self):
		super().__init__()

		self.TypeCovered = 0  # 2 bytes
		self.Algorithm = 0  # 1 byte
		self.Labels = 0  # 1 byte
		self.OrigTTL = 0  # 4 bytes
		self.SigExpi = 0  # 4 bytes
		self.SigInce = 0  # 4 bytes
		self.KeyTag = 0  # 2 bytes
		self.Signer = "".encode()  # name
		self.Signer_HEX = "".encode().hex()
		self.Signer_STR = ""
		self.Sig = "".encode()  # hex
		self.Sig_HEX = "".encode().hex()
		self.Sig_STR = ""

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, type_covered=0, algorithm=0, labels=0, orig_ttl=0,
				 sig_expi=0, sig_ince=0, key_tag=0, signer="", sig=""):
		super().setDNSRR(rrname, rtype, rclass, ttl)

		self.TypeCovered = type_covered
		self.Algorithm = algorithm
		self.Labels = labels
		self.OrigTTL = orig_ttl
		self.SigExpi = sig_expi
		self.SigInce = sig_ince
		self.KeyTag = key_tag
		self.Signer_STR = signer
		self.Signer_HEX = signer.encode().hex()
		self.Signer = ""
		labels = signer.split(".")
		label_number = len(labels)
		for i in range(0, label_number):
			self.Signer += chr(len(labels[i]))
			self.Signer += labels[i]
		self.Signer = self.Signer.encode()
		self.Sig_STR = sig
		self.Sig_HEX = sig.encode().hex()
		self.Sig = sig.encode()
		self.RDLEN = 2 + 1 + 1 + 4 + 4 + 4 + 2 + len(self.Signer) + len(self.Sig)

	def unsetDNSRR(self):
		super().unsetDNSRR()

		self.TypeCovered = 0
		self.Algorithm = 0
		self.Labels = 0
		self.OrigTTL = 0
		self.SigExpi = 0
		self.SigInce = 0
		self.KeyTag = 0
		self.Signer = "".encode()
		self.Signer_HEX = "".encode().hex()
		self.Signer_STR = ""
		self.Sig = "".encode()
		self.Sig_HEX = "".encode().hex()
		self.Sig_STR = ""

	def getDNSRR(self):
		return {"RRNAME": self.RRNAME_HEX, "RRNAME_STR": self.RRNAME_STR,
				"RTYPE": self.RTYPE, "RTYPE_STR": self.RTYPE_STR, "RCLASS": self.RCLASS, "RCLASS_STR": self.RCLASS_STR,
				"TTL": self.TTL, "RDLEN": self.RDLEN, "TypeCovered": self.TypeCovered, "Algorithm": self.Algorithm,
				"Labels": self.Labels, "OrigTTL": self.OrigTTL, "SigExpi": self.SigExpi, "SigInce": self.SigInce,
				"KeyTag": self.KeyTag, "Signer": self.Signer_HEX, "Signer_STR": self.Signer_STR, "Sig": self.Sig_HEX,
				"Sig_STR": self.Sig_STR}

	def makeDNSRR(self):
		return self.RRNAME + twoBytesField(self.RTYPE) + twoBytesField(self.RCLASS) + fourBytesField(
			self.TTL) + twoBytesField(self.RDLEN) + twoBytesField(self.TypeCovered) + oneByteField(
			self.Algorithm) + oneByteField(self.Labels) + fourBytesField(self.OrigTTL) + fourBytesField(
			self.SigExpi) + fourBytesField(self.SigInce) + twoBytesField(self.KeyTag) + self.Signer + self.Sig


# DNS resource record Type SPF
class DNSRRSPF(DNSRRTXT):
	"""DNS Resource Record Type SPF"""

	def __init__(self):
		super().__init__()

	def setDNSRR(self, rrname="", rtype=0, rclass=0, ttl=0, rdlen=0, spf=""):
		super().setDNSRR(rrname, rtype, rclass, ttl, rdlen, spf)

	def unsetDNSRR(self):
		super().unsetDNSRR()

	def getDNSRR(self):
		return super().getDNSRR()

	def makeDNSRR(self):
		return super().makeDNSRR()


DNSQRs = List[DNSQR]
DNSRRs = List[DNSRR]


class DNSFuzzer:
	"""DNS Fuzzer"""

	def __init__(self,
		domain_forward_only=domain_forward_only, 
		domain_forward_fallback=domain_forward_fallback, 
		domain_recursive=domain_recursive, 
		public_suffix="./public_suffix_list.dat",
		domain_list="./tlds-alpha-by-domain.txt",
		top_1m="./top-1m.csv"):
		
		self.domain_forward_only = domain_forward_only
		self.domain_forward_fallback = domain_forward_fallback
		self.domain_recursive = domain_recursive

		self.TXID = 0
		self.QR = 0
		self.OPCODE = 0
		self.AA = 0
		self.TC = 0
		self.RD = 0
		self.RA = 0
		self.Z = 0
		self.AD = 0
		self.CD = 0
		self.RCODE = 0
		self.QDCOUNT = 0
		self.ANCOUNT = 0
		self.NSCOUNT = 0
		self.ARCOUNT = 0
		self.QD: DNSQRs = []
		self.AN: DNSRRs = []
		self.NS: DNSRRs = []
		self.AR: DNSRRs = []

		self.TLD_list = []
		self.SLD_list = []
		self.TLD_list_len = 0
		self.SLD_list_len = 0
		self.TLD_map = {}

		with open(public_suffix, 'r') as file_r:
			for line in file_r:
				data = line.strip('\n')
				if data.startswith("//") or data == "":
					continue
				else:
					tld = data.encode("idna").decode().lower() + "."
					if tld in self.TLD_map.keys():
						continue
					else:
						self.TLD_map[tld] = True
						self.TLD_list.append(tld)

		with open(domain_list, 'r') as file_r:
			for line in file_r:
				data = line.strip('\n')
				if data.startswith("#"):
					continue
				else:
					tld = data.encode("idna").decode().lower() + "."
					if tld in self.TLD_map.keys():
						continue
					else:
						self.TLD_map[tld] = True
						self.TLD_list.append(tld)

		self.TLD_list_len = len(self.TLD_list)

		with open(top_1m, 'r') as file_r:
			for line in file_r:
				data = line.strip('\n').split(',')
				sld = data[1] + "."
				self.SLD_list.append(sld)

		self.SLD_list_len = len(self.SLD_list)

	def setTXID(self, txid=0):
		self.TXID = txid & (DNSFieldMaxValue["TXID"])

	def unsetTXID(self):
		self.TXID = 0

	def getTXID(self):
		return self.TXID

	def setQR(self):
		self.QR = 1

	def unsetQR(self):
		self.QR = 0

	def getQR(self):
		return self.QR

	def makeQR(self):
		return self.QR << DNSHeaderFlagBitPosition["QR"]

	def setOPCODE(self, opcode=0):
		self.OPCODE = opcode & (DNSFieldMaxValue["OPCODE"])

	def unsetOPCODE(self):
		self.OPCODE = 0

	def getOPCODE(self):
		return self.OPCODE

	def makeOPCODE(self):
		return self.OPCODE << DNSHeaderFlagBitPosition["OPCODE"]

	def setAA(self):
		self.AA = 1

	def unsetAA(self):
		self.AA = 0

	def getAA(self):
		return self.AA

	def makeAA(self):
		return self.AA << DNSHeaderFlagBitPosition["AA"]

	def setTC(self):
		self.TC = 1

	def unsetTC(self):
		self.TC = 0

	def getTC(self):
		return self.TC

	def makeTC(self):
		return self.TC << DNSHeaderFlagBitPosition["TC"]

	def setRD(self):
		self.RD = 1

	def unsetRD(self):
		self.RD = 0

	def getRD(self):
		return self.RD

	def makeRD(self):
		return self.RD << DNSHeaderFlagBitPosition["RD"]

	def setRA(self):
		self.RA = 1

	def unsetRA(self):
		self.RA = 0

	def getRA(self):
		return self.RA

	def makeRA(self):
		return self.RA << DNSHeaderFlagBitPosition["RA"]

	def setZ(self):
		self.Z = 1

	def unsetZ(self):
		self.Z = 0

	def getZ(self):
		return self.Z

	def makeZ(self):
		return self.Z << DNSHeaderFlagBitPosition["Z"]

	def setAD(self):
		self.AD = 1

	def unsetAD(self):
		self.AD = 0

	def getAD(self):
		return self.AD

	def makeAD(self):
		return self.AD << DNSHeaderFlagBitPosition["AD"]

	def setCD(self):
		self.CD = 1

	def unsetCD(self):
		self.CD = 0

	def getCD(self):
		return self.CD

	def makeCD(self):
		return self.CD << DNSHeaderFlagBitPosition["CD"]

	def setRCODE(self, rcode=0):
		self.RCODE = rcode & (DNSFieldMaxValue["OPCODE"])

	def unsetRCODE(self):
		self.RCODE = 0

	def getRCODE(self):
		return self.RCODE

	def makeRCODE(self):
		return self.RCODE << DNSHeaderFlagBitPosition["RCODE"]

	def setQDCOUNT(self, qdcount=1):
		self.QDCOUNT = qdcount & (DNSFieldMaxValue["QDCOUNT"])

	def unsetQDCOUNT(self):
		self.QDCOUNT = 0

	def getQDCOUNT(self):
		return self.QDCOUNT

	def makeQDCOUNT(self):
		return self.QDCOUNT

	def setANCOUNT(self, ancount=1):
		self.ANCOUNT = ancount & (DNSFieldMaxValue["ANCOUNT"])

	def unsetANCOUNT(self):
		self.ANCOUNT = 0

	def getANCOUNT(self):
		return self.ANCOUNT

	def makeANCOUNT(self):
		return self.ANCOUNT

	def setNSCOUNT(self, nscount=1):
		self.NSCOUNT = nscount & (DNSFieldMaxValue["NSCOUNT"])

	def unsetNSCOUNT(self):
		self.NSCOUNT = 0

	def getNSCOUNT(self):
		return self.NSCOUNT

	def makeNSCOUNT(self):
		return self.NSCOUNT

	def setARCOUNT(self, arcount=1):
		self.ARCOUNT = arcount & (DNSFieldMaxValue["ARCOUNT"])

	def unsetARCOUNT(self):
		self.ARCOUNT = 0

	def getARCOUNT(self):
		return self.ARCOUNT

	def makeARCOUNT(self):
		return self.ARCOUNT

	def setQD(self, qds: DNSQRs):
		self.QD = qds

	def unsetQD(self):
		self.QD = []

	def getQD(self):
		qds = []
		for qd in self.QD:
			qds.append(qd.getDNSQR())
		return qds

	def setAN(self, ans: DNSRRs):
		self.AN = ans

	def unsetAN(self):
		self.AN = []

	def getAN(self):
		ans = []
		for an in self.AN:
			ans.append(an.getDNSRR())
		return ans

	def setNS(self, nss: DNSRRs):
		self.NS = nss

	def unsetNS(self):
		self.NS = []

	def getNS(self):
		nss = []
		for ns in self.NS:
			nss.append(ns.getDNSRR())
		return nss

	def setAR(self, ars: DNSRRs):
		self.AR = ars

	def unsetAR(self):
		self.AR = []

	def getAR(self):
		ars = []
		for ar in self.AR:
			ars.append(ar.getDNSRR())
		return ars

	def makeTXID(self):
		return twoBytesField(self.getTXID())

	def makeHeaderFlag(self):
		return oneByteField(self.makeQR() | self.makeOPCODE() | self.makeAA() | self.makeTC() | self.makeRD()) + \
			   oneByteField(self.makeRA() | self.makeZ() | self.makeAD() | self.makeCD() | self.makeRCODE())

	def makeRRCount(self):
		return twoBytesField(self.makeQDCOUNT()) + twoBytesField(self.makeANCOUNT()) + \
			   twoBytesField(self.makeNSCOUNT()) + twoBytesField(self.makeARCOUNT())

	def makeQD(self):
		qds = "".encode()
		for qd in self.QD:
			qds += qd.makeDNSQR()
		return qds

	def makeAN(self):
		ans = "".encode()
		for an in self.AN:
			ans += an.makeDNSRR()
		return ans

	def makeNS(self):
		nss = "".encode()
		for ns in self.NS:
			nss += ns.makeDNSRR()
		return nss

	def makeAR(self):
		ars = "".encode()
		for ar in self.AR:
			ars += ar.makeDNSRR()
		return ars

	def makeDNSPkt(self):
		return self.makeTXID() + self.makeHeaderFlag() + self.makeRRCount() + self.makeQD() + self.makeAN() + \
			   self.makeNS() + self.makeAR()

	def makeDNSHeaderCount(self):
		return self.makeHeaderFlag() + self.makeRRCount()

	def makeDNSANNSAR(self):
		return self.makeAN() + self.makeNS() + self.makeAR()

	def Unset(self):
		self.unsetTXID()
		self.unsetQR()
		self.unsetOPCODE()
		self.unsetAA()
		self.unsetTC()
		self.unsetRD()
		self.unsetRA()
		self.unsetZ()
		self.unsetAD()
		self.unsetCD()
		self.unsetRCODE()
		self.unsetQDCOUNT()
		self.unsetANCOUNT()
		self.unsetNSCOUNT()
		self.unsetARCOUNT()
		self.unsetQD()
		self.unsetAN()
		self.unsetNS()
		self.unsetAR()

	def DumpPkt(self):
		pkt = {"TXID": self.getTXID(), "QR": self.getQR(), "OPCODE": self.getOPCODE(), "AA": self.getAA(),
			   "TC": self.getTC(), "RD": self.getRD(), "RA": self.getRA(), "Z": self.getZ(), "AD": self.getAD(),
			   "CD": self.getCD(), "RCODE": self.getRCODE(), "RCODE_STR": DNSRCodes(self.getRCODE()).name,
			   "QDCOUNT": self.getQDCOUNT(), "ANCOUNT": self.getANCOUNT(),
			   "NSCOUNT": self.getNSCOUNT(), "ARCOUNT": self.getARCOUNT(),
			   "QD": self.getQD(), "AN": self.getAN(), "NS": self.getNS(), "AR": self.getAR()}

		return json.dumps(pkt)

	def LoadPkt(self, pktStr):
		self.Unset()

		pkt = json.loads(pktStr)

		# Load txid
		self.setTXID(pkt["TXID"])

		# Load qr
		if pkt["QR"] == 1:
			self.setQR()
		else:
			self.unsetQR()

		# Load opcode
		self.setOPCODE(pkt["OPCODE"])

		# Load aa
		if pkt["AA"] == 1:
			self.setAA()
		else:
			self.unsetAA()

		# Load tc
		if pkt["TC"] == 1:
			self.setTC()
		else:
			self.unsetTC()

		# Load rd
		if pkt["RD"] == 1:
			self.setRD()
		else:
			self.unsetRD()

		# Load ra
		if pkt["RA"] == 1:
			self.setRA()
		else:
			self.unsetRA()

		# Load z
		if pkt["Z"] == 1:
			self.setZ()
		else:
			self.unsetZ()

		# Load ad
		if pkt["AD"] == 1:
			self.setAD()
		else:
			self.unsetAD()

		# Load cd
		if pkt["CD"] == 1:
			self.setCD()
		else:
			self.unsetCD()

		# Load rcode
		self.setRCODE(pkt["RCODE"])

		# Generate qd
		qd_count = pkt["QDCOUNT"]
		self.setQDCOUNT(qd_count)
		qds = []
		for qd_ in pkt["QD"]:
			qd = DNSQR()
			qname = bytes.fromhex(qd_["QNAME"]).decode()
			qtype = qd_["QTYPE"]
			qclass = qd_["QTYPE"]
			qd.setDNSQR(qname, qtype, qclass)
			qds.append(qd)
		self.setQD(qds)

	def makeName(self):
		random.seed()

		charset = string.digits + string.ascii_lowercase + string.punctuation[:13] + string.punctuation[14:]

		name = ""
		label_number_base = 0
		choice_base = random.randint(9, 40)
		if choice_base == 0:
			name = "."
			label_number_base = 0
		elif choice_base <= 4:
			name = self.TLD_list[random.randint(0, self.TLD_list_len - 1)]
			label_number_base = len(name.split('.'))
		elif choice_base <= 8:
			name = self.SLD_list[random.randint(0, self.SLD_list_len - 1)]
			label_number_base = len(name.split('.'))
		elif choice_base <= 16:
			name = self.domain_forward_only
			label_number_base = len(name.strip('.').split('.'))
		elif choice_base <= 24:
			name = self.domain_forward_fallback
			label_number_base = len(name.strip('.').split('.'))
		else:
			name = self.domain_recursive
			label_number_base = len(name.strip('.').split('.'))

		choice_label_num = random.randint(0, 9)
		label_number = 0
		if choice_label_num <= 3:
			return name
		elif choice_label_num <= 7:
			label_number = 1 + label_number_base
		elif choice_label_num == 8:
			label_number = random.randint(2, 9) + label_number_base
		else:
			label_number = random.randint(10, DNSFieldMaxValue["LABELNUM"] - label_number_base) + label_number_base
		label_length_max = DNSFieldMaxValue["LABELLEN"]
		if label_length_max > int(DNSFieldMaxValue["NAMELEN"] / label_number):
			label_length_max = int(DNSFieldMaxValue["NAMELEN"] / label_number)

		for i in range(0, label_number - label_number_base):
			label = ""
			label_length = random.randint(1, label_length_max)
			label = ''.join(random.sample(charset, label_length))
			name = label + "." + name

		name = name.rstrip(".") + "."

		return name

	def QueryMore(self):
		random.seed()

		# Generate txid
		self.setTXID(random.randint(0, DNSFieldMaxValue["TXID"]))

		# Generate qr
		if random.randint(0, 1) == 2:
			self.setQR()
		else:
			self.unsetQR()

		# Generate opcode
		if random.randint(0, 4) == 0:
			self.setOPCODE(DNSOpCodes.valueList()[random.randint(0, len(DNSOpCodes) - 1)])
		else:
			self.setOPCODE(DNSOpCodesCommon.valueList()[random.randint(0, len(DNSOpCodesCommon) - 1)])

		# Generate aa
		if random.randint(0, 1) == 1:
			self.setAA()
		else:
			self.unsetAA()

		# Generate tc
		if random.randint(0, 1) == 1:
			self.setTC()
		else:
			self.unsetTC()

		# Generate rd
		if random.randint(0, 1) == 1:
			self.setRD()
		else:
			self.unsetRD()

		# Generate ra
		if random.randint(0, 1) == 1:
			self.setRA()
		else:
			self.unsetRA()

		# Generate z
		if random.randint(0, 1) == 1:
			self.setZ()
		else:
			self.unsetZ()

		# Generate ad
		if random.randint(0, 1) == 1:
			self.setAD()
		else:
			self.unsetAD()

		# Generate cd
		if random.randint(0, 1) == 1:
			self.setCD()
		else:
			self.unsetCD()

		# Generate rcode
		if random.randint(0, 4) == 0:
			self.setRCODE(DNSRCodes.valueList()[random.randint(0, len(DNSRCodes) - 1)])
		else:
			self.setRCODE(DNSRCodesCommon.valueList()[random.randint(0, len(DNSRCodesCommon) - 1)])

		# Generate qd
		choice = random.randint(0, 6)
		equal = random.randint(-1, 5)
		qd_count = 0
		qd_number = 0
		if choice == 0:
			qd_count = 0
			if equal <= 3:
				qd_number = qd_count
			elif equal == 4:
				qd_number = qd_count + 1
			else:
				qd_number = qd_count + random.randint(1, DNSFieldMaxValue["QDCOUNT"] - qd_count)
		elif choice <= 4:
			qd_count = 1
			if equal == -1:
				qd_number = 0
			elif equal <= 3:
				qd_number = qd_count
			elif equal == 4:
				qd_number = qd_count + 1
			else:
				qd_number = qd_count + random.randint(2, DNSFieldMaxValue["QDCOUNT"] - qd_count)
		elif choice == 5:
			qd_count = 2
			if equal == -1:
				qd_number = qd_count - random.randint(1, qd_count)
			elif equal <= 3:
				qd_number = qd_count
			elif equal == 4:
				qd_number = qd_count + 1
			else:
				qd_number = qd_count + random.randint(2, DNSFieldMaxValue["QDCOUNT"] - qd_count)
		else:
			qd_count = random.randint(3, DNSFieldMaxValue["QDCOUNT"])
			if equal == -1:
				qd_number = qd_count - random.randint(1, qd_count)
			elif equal <= 3:
				qd_number = qd_count
			elif equal == 4:
				qd_number = qd_count + 1
			else:
				qd_number = qd_count + random.randint(2, DNSFieldMaxValue["QDCOUNT"] - qd_count)
		self.setQDCOUNT(qd_count)
		qds = []
		print(qd_count, qd_number)
		for i in range(0, qd_number):
			qd = DNSQR()
			qname = self.makeName()
			print(qname)
			qtype = 0
			if random.randint(0, 4) == 0:
				qtype = DNSTypes.valueList()[random.randint(0, len(DNSTypes) - 1)]
			else:
				qtype = DNSTypesCommon.valueList()[random.randint(0, len(DNSTypesCommon) - 1)]
			qclass = 0
			if random.randint(0, 4) == 0:
				qclass = DNSClasses.valueList()[random.randint(0, len(DNSClasses) - 1)]
			else:
				qclass = DNSClassesCommon.valueList()[random.randint(0, len(DNSClassesCommon) - 1)]
			qd.setDNSQR(qname, qtype, qclass)
			qds.append(qd)
		self.setQD(qds)

		return self.makeDNSPkt()

	def ResponseTmp(self, txid=0, queries=None, new=True):
		random.seed()

		if queries is None:
			queries = [("google.com.", DNSTypes.A.value, DNSClasses.IN.value)]

		#
		# No re-generation
		if not new:
			# Set txid
			self.setTXID(txid)

			# Generate qd
			self.setQDCOUNT(len(queries))

			qds = []
			for query in queries:
				qd = DNSQR()
				qd.setDNSQR(query[0], query[1], DNSClasses.IN.value)
				qds.append(qd)
			self.setQD(qds)

			return self.makeDNSPkt()

		#
		# New generation

		# Set txid
		self.setTXID(txid)

		# Generate response
		self.setQR()

		# Generate opcode
		if random.randint(0, 4) == 0:
			self.setOPCODE(DNSOpCodes.valueList()[random.randint(0, len(DNSOpCodes) - 1)])
		else:
			self.setOPCODE(DNSOpCodesCommon.valueList()[random.randint(0, len(DNSOpCodesCommon) - 1)])

		# Generate aa
		if random.randint(0, 1) == 1:
			self.setAA()
		else:
			self.unsetAA()

		# Generate tc
		if random.randint(0, 1) == 1:
			self.setTC()
		else:
			self.unsetTC()

		# Generate rd
		if random.randint(0, 1) == 1:
			self.setRD()
		else:
			self.unsetRD()

		# Generate ra
		if random.randint(0, 1) == 1:
			self.setRA()
		else:
			self.unsetRA()

		# Generate z
		if random.randint(0, 1) == 1:
			self.setZ()
		else:
			self.unsetZ()

		# Generate ad
		if random.randint(0, 1) == 1:
			self.setAD()
		else:
			self.unsetAD()

		# Generate cd
		if random.randint(0, 1) == 1:
			self.setCD()
		else:
			self.unsetCD()

		# Generate rcode
		if random.randint(0, 4) == 0:
			self.setRCODE(DNSRCodes.valueList()[random.randint(0, len(DNSRCodes) - 1)])
		else:
			self.setRCODE(DNSRCodesCommon.valueList()[random.randint(0, len(DNSRCodesCommon) - 1)])

		# Generate qd
		self.setQDCOUNT(len(queries))

		qds = []
		for query in queries:
			qd = DNSQR()
			qd.setDNSQR(query[0], query[1], query[2])
			qds.append(qd)
		self.setQD(qds)

		# Generate an
		self.setANCOUNT(3)
		ans = []

		an = DNSRRTXT()
		an.setDNSRR("baidu.com.", DNSTypes.TXT.value, DNSClasses.IN.value, 0, len("test"), "test")
		ans.append(an)

		an = DNSRRAAAA()
		an.setDNSRR("baidu.com.", DNSTypes.AAAA.value, DNSClasses.IN.value, 0, 16, "2001::")
		ans.append(an)

		an = DNSRRRRSIG()
		an.setDNSRR("baidu.com.", DNSTypes.RRSIG.value, DNSClasses.IN.value, 0, 0, DNSTypes.AAAA.value,
					DNSSECAlgNums.RSASHA1.value, 2, 0, 0, 0, 0, "baidu.com.", "signature")
		ans.append(an)

		self.setAN(ans)

		return self.makeDNSPkt()

	def makeNameData(self, name):
		choice_base = random.randint(0, 4)
		if choice_base == 0:
			return name
		elif choice_base == 1:
			return "sub." + name
		elif choice_base == 2:
			return "new-" + name
		elif choice_base == 3:
			return ".".join(name.split(".")[1:])
		else:
			return self.makeName()

	def makeRR(self, rrname, rtype, rclass, ttl):
		rr = DNSRR()
		if rtype == DNSTypes.A.value:
			rr = DNSRRA()
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, "1.2.3.4")
		elif rtype == DNSTypes.NS.value:
			rr = DNSRRNS()
			ns = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, ns)  # ns and glue exception
		elif rtype == DNSTypes.CNAME.value:
			rr = DNSRRCNAME()
			cname = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, cname)
		elif rtype == DNSTypes.DNAME.value:
			rr = DNSRRDNAME()
			dname = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, dname)
		elif rtype == DNSTypes.SOA.value:
			rr = DNSRRSOA()
			mname = self.makeNameData(rrname)
			rname = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, mname, rname)
		elif rtype == DNSTypes.PTR.value:
			rr = DNSRRPTR()
			ptr = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, ptr)
		elif rtype == DNSTypes.MX.value:
			rr = DNSRRMX()
			mx = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, 0, mx)
		elif rtype == DNSTypes.TXT.value:
			rr = DNSRRTXT()
			txt = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, txt)
		elif rtype == DNSTypes.AAAA.value:
			rr = DNSRRAAAA()
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, "2001::1234")
		elif rtype == DNSTypes.RRSIG.value:
			rr = DNSRRRRSIG()
			signer = self.makeNameData(rrname)
			rr.setDNSRR(rrname, rtype, rclass, ttl, 0, DNSTypes.A.value, DNSSECAlgNums.RSASHA1.value, 2, 0, 0, 0, 0,
						signer, "signature")
		elif rtype == DNSTypes.SPF.value:
			rr = DNSRRSPF()
			spf = self.makeNameData(rrname)
			rr.setDNSRR(rrname, DNSTypes.TXT.value, rclass, ttl, 0, spf)
		else:
			return None
		return rr

	def Query(self):
		random.seed()

		# Generate txid
		self.setTXID(random.randint(0, DNSFieldMaxValue["TXID"]))

		# Generate qr
		if random.randint(0, 1) == 2:
			self.setQR()
		else:
			self.unsetQR()

		# Generate opcode
		if random.randint(0, 4) == 0:
			self.setOPCODE(DNSOpCodes.valueList()[random.randint(0, len(DNSOpCodes) - 1)])
		else:
			self.setOPCODE(DNSOpCodesCommon.valueList()[random.randint(0, len(DNSOpCodesCommon) - 1)])

		# Generate aa
		if random.randint(0, 1) == 1:
			self.setAA()
		else:
			self.unsetAA()

		# Generate tc
		if random.randint(0, 1) == 1:
			self.setTC()
		else:
			self.unsetTC()

		# Generate rd
		if random.randint(0, 1) == 1:
			self.setRD()
		else:
			self.unsetRD()

		# Generate ra
		if random.randint(0, 1) == 1:
			self.setRA()
		else:
			self.unsetRA()

		# Generate z
		if random.randint(0, 1) == 1:
			self.setZ()
		else:
			self.unsetZ()

		# Generate ad
		if random.randint(0, 1) == 1:
			self.setAD()
		else:
			self.unsetAD()

		# Generate cd
		if random.randint(0, 1) == 1:
			self.setCD()
		else:
			self.unsetCD()

		# Generate rcode
		if random.randint(0, 4) == 0:
			self.setRCODE(DNSRCodes.valueList()[random.randint(0, len(DNSRCodes) - 1)])
		else:
			self.setRCODE(DNSRCodesCommon.valueList()[random.randint(0, len(DNSRCodesCommon) - 1)])

		# Generate qd
		qd_count = 1
		qd_number = 1
		self.setQDCOUNT(qd_count)
		qds = []
		for i in range(0, qd_number):
			qd = DNSQR()
			qname = self.makeName()
			print(qname)
			qtype = DNSTypesCommon.valueList()[random.randint(0, len(DNSTypesCommon) - 1)]
			qclass = DNSClassesCommon.valueList()[random.randint(0, len(DNSClassesCommon) - 1)]
			qd.setDNSQR(qname, qtype, qclass)
			qds.append(qd)
		self.setQD(qds)

		return self.makeDNSPkt().hex()

	def Response(self):
		random.seed()

		qname = "google.com."
		qtype = DNSTypes.A.value
		qclass = DNSClasses.IN.value
		ttl = 60

		if len(self.QD) > 0:
			qname = self.QD[0].QNAME_STR
			qtype = self.QD[0].QTYPE
			qclass = self.QD[0].QCLASS

		# Generate response
		self.setQR()

		# Generate opcode
		if random.randint(0, 4) == 0:
			self.setOPCODE(DNSOpCodes.valueList()[random.randint(0, len(DNSOpCodes) - 1)])
		else:
			self.setOPCODE(DNSOpCodesCommon.valueList()[random.randint(0, len(DNSOpCodesCommon) - 1)])

		# Generate aa
		if random.randint(0, 1) == 1:
			self.setAA()
		else:
			self.unsetAA()

		# Generate tc
		if random.randint(0, 1) == 1:
			self.setTC()
		else:
			self.unsetTC()

		# Generate rd
		if random.randint(0, 1) == 1:
			self.setRD()
		else:
			self.unsetRD()

		# Generate ra
		if random.randint(0, 1) == 1:
			self.setRA()
		else:
			self.unsetRA()

		# Generate z
		if random.randint(0, 1) == 1:
			self.setZ()
		else:
			self.unsetZ()

		# Generate ad
		if random.randint(0, 1) == 1:
			self.setAD()
		else:
			self.unsetAD()

		# Generate cd
		if random.randint(0, 1) == 1:
			self.setCD()
		else:
			self.unsetCD()

		# Generate rcode
		if random.randint(0, 4) == 0:
			self.setRCODE(DNSRCodes.valueList()[random.randint(0, len(DNSRCodes) - 1)])
		else:
			self.setRCODE(DNSRCodesCommon.valueList()[random.randint(0, len(DNSRCodesCommon) - 1)])

		# Generate qd
		self.setQDCOUNT(1)

		# Generate an&ns&ar
		an_count = random.randint(0, 5)
		ns_count = random.randint(0, 5)
		ar_count = random.randint(0, 5)

		self.setANCOUNT(an_count)
		self.setNSCOUNT(ns_count)
		self.setARCOUNT(ar_count)

		ans = []
		for i in range(0, an_count):
			rrname = self.makeNameData(qname)
			if random.randint(0, 1) == 0 and qtype != DNSTypesCommon.ANY.value:
				rtype = qtype
			else:
				rtype = DNSTypesCommonNoANY.valueList()[random.randint(0, len(DNSTypesCommonNoANY) - 1)]
			rclass = qclass
			an = self.makeRR(rrname, rtype, rclass, ttl)
			ans.append(an)
		self.setAN(ans)

		nss = []
		for i in range(0, ns_count):
			rrname = self.makeNameData(qname)
			if random.randint(0, 1) == 0 and qtype != DNSTypesCommon.ANY.value:
				rtype = qtype
			else:
				rtype = DNSTypesCommonNoANY.valueList()[random.randint(0, len(DNSTypesCommonNoANY) - 1)]
			rclass = qclass
			ns = self.makeRR(rrname, rtype, rclass, ttl)
			nss.append(ns)
		self.setNS(nss)

		ars = []
		for i in range(0, ar_count):
			rrname = self.makeNameData(qname)
			if random.randint(0, 1) == 0 and qtype != DNSTypesCommon.ANY.value:
				rtype = qtype
			else:
				rtype = DNSTypesCommonNoANY.valueList()[random.randint(0, len(DNSTypesCommonNoANY) - 1)]
			rclass = qclass
			ar = self.makeRR(rrname, rtype, rclass, ttl)
			ars.append(ar)
		self.setAR(ars)

		return self.makeDNSHeaderCount().hex(), self.makeDNSANNSAR().hex()


def test():
	print(twoBytesField(2))
	df = DNSFuzzer()
	print(df.makeTXID())
	df.setRD()
	df.setAD()
	print(df.makeHeaderFlag())
	df.setQDCOUNT()
	print(df.makeRRCount())
	print((df.makeTXID() + df.makeHeaderFlag() + df.makeRRCount()).hex())
	name = "baidu.com."
	print(name.encode().hex())
	print(bytes.fromhex(name.encode().hex()).decode())
	print(name.split("."))
	question = ""
	parts = name.split(".")
	quant = len(parts)
	for i in parts:
		print(i)
	for i in range(0, quant):
		question += chr(len(parts[i]))
		question += parts[i]
	print(question.encode().hex())
	print(df.makeDNSPkt().hex())
	print(len(DNSRCodes))
	print(DNSTypes.A)
	print(DNSTypes.A.name)
	print(DNSTypes.A.value)
	print(DNSTypes.nameList())
	print(len(DNSRCodes.valueList()))
	dns_query = df.Query()
	print(dns_query.hex())


def send_tcp(src_ip, src_port, dst_ip, dst_port, payload):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.bind((src_ip, src_port))
	client.connect((dst_ip, dst_port))
	client.settimeout(1)
	client.sendall(twoBytesField(len(payload)) + payload)
	# data = client.recv(65536)
	# client.close()
	#
	# print(data[2:].hex())


def send_udp(src_ip, src_port, dst_ip, dst_port, payload):
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	client.bind((src_ip, src_port))
	client.settimeout(1)
	client.sendto(payload, (dst_ip, dst_port))
	# data, _ = client.recvfrom(65536)
	# client.close()
	#
	# print(data.hex())


if __name__ == "__main__":
	df = DNSFuzzer()
	dns_query = df.Query()
	print(dns_query.hex())
	send_udp("166.111.132.232", 12345, "1.2.3.4", 53, dns_query)
	header_count, annsar = df.Response()
	dns_response = df.makeTXID() + header_count + df.makeQD() + annsar
	send_udp("166.111.132.232", 12345, "1.2.3.4", 53, dns_response)
