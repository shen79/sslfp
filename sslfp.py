#!/usr/bin/python

import socket
import sys
from struct import pack, unpack
from binascii import hexlify
from operator import setitem
import pprint


class Chucky:
	def __init__(self, params):
		self.ptr = 0				# pointer used while parsing section data
		self.sect_data = ""			# section data
		self.host = params['host']
		self.port = params['port']
		self.client_hello = {}
		self.results = {}
		
		self.last_ct = ""
		self.last_hst = ""

		self.ext = {} # TODO
		self.ext['ec_point_fmt'] = "\x00\x0b\x00\x02\x01\x00" 
		self.ext['sessionticket_tls'] = "\x00\x23\x00\x00" 
#		self.ext['next_proto_negotiation'] = "\x33\x74\x00\x00" 
		self.ext['next_proto_negotiation'] = "\x33\x74\x00\x00" 
		self.ext['status_request'] = "\x00\x05\x00\x05\x01\x00\x00\x00\x00" 
		self.ext['signature_algos'] = "\x00\x0d\x00\x16\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02" 

	trans = {
		'cipher-suite': {
			0x0000: 'SSL_NULL_WITH_NULL_NULL',
			0x0001: 'SSL_RSA_WITH_NULL_MD5',
			0x0002: 'SSL_RSA_WITH_NULL_SHA',
			0x0003: 'SSL_RSA_EXPORT_WITH_RC4_40_MD5',
			0x0004: 'SSL_RSA_WITH_RC4_128_MD5',
			0x0005: 'SSL_RSA_WITH_RC4_128_SHA',
			0x0006: 'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
			0x0007: 'SSL_RSA_WITH_IDEA_CBC_SHA',
			0x0008: 'SSL_RSA_EXPORT_WITH_DES40_CBC_SHA',
			0x0009: 'SSL_RSA_WITH_DES_CBC_SHA',
			0x000A: 'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
			0x000B: 'SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
			0x000C: 'SSL_DH_DSS_WITH_DES_CBC_SHA',
			0x000D: 'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA',
			0x000E: 'SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
			0x000F: 'SSL_DH_RSA_WITH_DES_CBC_SHA',
			0x0010: 'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA',
			0x0011: 'SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
			0x0012: 'SSL_DHE_DSS_WITH_DES_CBC_SHA',
			0x0013: 'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
			0x0014: 'SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
			0x0015: 'SSL_DHE_RSA_WITH_DES_CBC_SHA',
			0x0016: 'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
			0x0017: 'SSL_DH_anon_EXPORT_WITH_RC4_40_MD5',
			0x0018: 'SSL_DH_anon_WITH_RC4_128_MD5',
			0x0019: 'SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
			0x001A: 'SSL_DH_anon_WITH_DES_CBC_SHA',
			0x001B: 'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA',
			0x001C: 'SSL_FORTEZZA_DMS_WITH_NULL_SHA',
			0x001D: 'SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA',
			# TLS addenda using AES: 'per RFC 3268
			0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
			0x0030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
			0x0031: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
			0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
			0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
			0x0034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
			0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
			0x0036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
			0x0037: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
			0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
			0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
			0x003A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
			# ECDSA addenda: 'RFC 4492
			0xC001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
			0xC002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
			0xC003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
			0xC004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
			0xC005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
			0xC006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
			0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
			0xC008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
			0xC009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
			0xC00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
			0xC00B: 'TLS_ECDH_RSA_WITH_NULL_SHA',
			0xC00C: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
			0xC00D: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
			0xC00E: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
			0xC00F: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
			0xC010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
			0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
			0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
			0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
			0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
			0xC015: 'TLS_ECDH_anon_WITH_NULL_SHA',
			0xC016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
			0xC017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
			0xC018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
			0xC019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
			# TLS 1.2 addenda: 'RFC 5246
			# Initial state.
			0x0000: 'TLS_NULL_WITH_NULL_NULL',
			# Server provided RSA certificate for key exchange.
			0x0001: 'TLS_RSA_WITH_NULL_MD5',
			0x0002: 'TLS_RSA_WITH_NULL_SHA',
			0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
			0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
			0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
			0x002F: '//TLS_RSA_WITH_AES_128_CBC_SHA',
			0x0035: '//TLS_RSA_WITH_AES_256_CBC_SHA',
			0x003B: 'TLS_RSA_WITH_NULL_SHA256',
			0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
			0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
			# Server-authenticated (and optionally client-authenticated) Diffie-Hellman.
			0x000D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
			0x0010: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
			0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
			0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
			0x0030: '//TLS_DH_DSS_WITH_AES_128_CBC_SHA',
			0x0031: '//TLS_DH_RSA_WITH_AES_128_CBC_SHA',
			0x0032: '//TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
			0x0033: '//TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
			0x0036: '//TLS_DH_DSS_WITH_AES_256_CBC_SHA',
			0x0037: '//TLS_DH_RSA_WITH_AES_256_CBC_SHA',
			0x0038: '//TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
			0x0039: '//TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
			0x003E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
			0x003F: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
			0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
			0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
			0x0068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
			0x0069: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
			0x006A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
			0x006B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
			# Completely anonymous Diffie-Hellman
			0x0018: 'TLS_DH_anon_WITH_RC4_128_MD5',
			0x001B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
			0x0034: '//TLS_DH_anon_WITH_AES_128_CBC_SHA',
			0x003A: '//TLS_DH_anon_WITH_AES_256_CBC_SHA',
			0x006C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
			0x006D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
			# Addenda from rfc 5288 AES Galois Counter Mode (GCM) Cipher Suites for TLS.
			0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
			0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
			0x009E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
			0x009F: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
			0x00A0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
			0x00A1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
			0x00A2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
			0x00A3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
			0x00A4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
			0x00A5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
			0x00A6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
			0x00A7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
			# Addenda from rfc 5289  Elliptic Curve Cipher Suites with HMAC SHA-256/384.
			0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
			0xC024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
			0xC025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
			0xC026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
			0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
			0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
			0xC029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
			0xC02A: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
			# Addenda from rfc 5289  Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
			0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
			0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
			0xC02D: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
			0xC02E: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
			0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
			0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
			0xC031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
			0xC032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
			# RFC 5746 - Secure Renegotiation
			0x00FF: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
			# Tags for SSL 2 cipher kinds which are not specified for SSL 3.
			0xFF80: 'SSL_RSA_WITH_RC2_CBC_MD5',
			0xFF81: 'SSL_RSA_WITH_IDEA_CBC_MD5',
			0xFF82: 'SSL_RSA_WITH_DES_CBC_MD5',
			0xFF83: 'SSL_RSA_WITH_3DES_EDE_CBC_MD5',
			0xFFFF: 'SSL_NO_SUCH_CIPHERSUITE'
		},
		'extension-type': {
			# http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
			0:	'server_name',					# [RFC6066]
			1:	'max_fragment_length',			# [RFC6066]
			2:	'client_certificate_url',		# [RFC6066]
			3:	'trusted_ca_keys',				# [RFC6066]
			4:	'truncated_hmac',				# [RFC6066]
			5:	'status_request',				# [RFC6066]
			6:	'user_mapping',					# [RFC4681]
			7:	'client_authz',					# [RFC5878]
			8:	'server_authz',					# [RFC5878]
			9:	'cert_type',					# [RFC6091]
			10:	'supported_groups',				# (renamed from "elliptic_curves") 	[RFC4492][RFC-ietf-tls-negotiated-ff-dhe-10]
			11:	'ec_point_formats',				# [RFC4492]
			12:	'srp',							# [RFC5054]
			13:	'signature_algorithms',			# [RFC5246]
			14:	'use_srtp',						# [RFC5764]
			15:	'heartbeat',					# [RFC6520]
			16:	'application_layer_protocol_negotiation', # [RFC7301]
			17:	'status_request_v2',			# [RFC6961]
			18:	'signed_certificate_timestamp', # [RFC6962]
			19:	'client_certificate_type',		# [RFC7250]
			20:	'server_certificate_type', 		# [RFC7250]
			21:	'padding', 						# (TEMPORARY - registered 2014-03-12, expires 2016-03-12) 	[draft-ietf-tls-padding]
			22:	'encrypt_then_mac', 			# [RFC7366]
			23: 'extended_master_secret',		# [RFC-ietf-tls-session-hash-06]
			#24-34 	Unassigned 	
			35: 'SessionTicket TLS', 			# [RFC4507]
			0x3374: 'next_protocol_negiotiation', # 13172, 
			#36-65280 	Unassigned 	
			65281: 'renegotiation_info', 		# [RFC5746]
			#65282-65535 	Unassigned
		},
		'version': {
			0x0301: 'TLSv1.0',
			0x0303: 'TLSv1.2',
		},
		'content-type': {
			0x16: 'Handshake'
		},
		'handshake-type': {
			0x02: 'Server-Hello',
			0x0b: 'Certificate',
			0x0c: 'Server Key Exchange',
			0x0e: 'Server-Hello done',
		},
		'compression-method': {
			0x00: 'Null'
		},
	}


# ___ EXT: SERVER NAME _____________________________________________________________________________
	def ext_server_name(self):
		_NAME_TYPE_HOSTNAME = 0
		_EXT_TYPE_SERVER_NAME = 0
		server_name = self.host
		snix = pack('>H', _NAME_TYPE_HOSTNAME) + pack('B', len(server_name)) + server_name
		snix = pack('>H', len(snix)) + snix
		self.ext['server_name'] = pack('>H', _EXT_TYPE_SERVER_NAME) + pack('>H', len(snix)) + snix

# ___ EXT: RENEGOTIATION INFO ______________________________________________________________________
	def ext_renegiotiation(self):
		_EXT_TYPE_RENEGOTIATION_INFO = 0xff01 # ext: renegotiation info
		self.ext['reneg_info'] = pack('H', _EXT_TYPE_RENEGOTIATION_INFO)
		self.ext['reneg_info'] = self.ext['reneg_info'] + pack('H', 1) + pack('B', 0)

# ___ EXT: ELLIPTIC ________________________________________________________________________________
	def ext_alliptic_curves(self):
		_EXT_TYPE_ELLIPTIC_CURVES = 0x000a
		curves_l = [0x17, 0x18, 0x19]
		curves = pack('H' * len(curves_l), *curves_l) # curves
		curves = pack('H', len(curves)) + curves	# length 8
		curves = pack('H', len(curves)) + curves	# curves length 6
		self.ext['elliptic'] = pack('H', _EXT_TYPE_RENEGOTIATION_INFO) + curves

	def build_ext(self):
		ext_raw = ""
		for k in self.ext:
			ext_raw += self.ext[k]
		ext_len = pack('>H', len(ext_raw))
		self.client_hello['extensions'] = ext_len + ext_raw

	def handshake_version(self):
		_VERSION_TLS12 = 0x0303
		_VERSION_TLS11 = 0x0302
		_VERSION_TLS10 = 0x0301
		_VERSION_SSL30 = 0x0300
		_VERSION_SSL20 = 0x0002
		self.client_hello['handshake_version'] = pack('>H', _VERSION_TLS12)
#		return pack('>H', _VERSION_TLS12)	# version tls 1.2

	def timestamp(self):
		self.client_hello['timestamp'] = "\xc8\x8c\x95\xf3" 			# gmt unix timestamp

	def rand(self):
		self.client_hello['random'] = "\x00" * 28					# random

	def session_id_length(self):
		return "\x00" 						# sess id length

	def cypher_suites(self):
		cypher_suites_raw = "\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\xc0\x12\xc0\x07\xc0\x11\x00\x33\x00\x32\x00\x45\x00\x39\x00\x38\x00\x88\x00\x16\x00\x2f\x00\x41\x00\x35\x00\x84\x00\x0a\x00\x05\x00\x04" 
		cypher_suites_len = pack('>H', len(cypher_suites_raw))
		self.client_hello['cypher-suites'] = cypher_suites_len + cypher_suites_raw

# ___ EXT: COMPRESSION_METHODS _____________________________________________________________________
	def compression(self):
		return pack('BB', 1, 0) # 0ne method: null

	def handshake_type(self):
#		if self._handshake_type
		return "\x01" 				# handshake type: client hello

	def build_packet(self):
		self.handshake_version()
		self.timestamp()
		self.rand()
		self.cypher_suites()
		self.build_ext()
		cth_data_raw = ''.join([
			self.client_hello['handshake_version'],
			self.client_hello['timestamp'],
			self.client_hello['random'],
			self.session_id_length(),
			self.client_hello['cypher-suites'],
			self.compression(),
			self.client_hello['extensions']
		])
	#	return self.cth_data_raw
		cth_data_len = "\x00" + pack('>H', len(cth_data_raw)) # length
		cth_raw = self.handshake_type() + cth_data_len + cth_data_raw

		ct  = pack('B', 0x16)		# content-type
		ver = pack('>H', 0x0301)	# version tls 1.0
		cth_len = pack('>H', len(cth_raw))
		ct_hello = ct + ver + cth_len + cth_raw

		a = 0
		if a == 1:
			print self.ct_hello
			sys.exit()
		return ct_hello

	def hello(self):
		"""
		Build hello packet and send it
		"""
		try:
			sock = socket.socket()
			sock.connect((host, port))
		except socket.error as e:
			print e
			sys.exit(1)

		ssldata = self.build_packet()
		sock.send(ssldata)
		self.sect_data = sock.recv(0xfff)
		self.parse_response()

	
	def attack(self, field, values):
		pass


	def get(self, sect_name, n, rawdata=False):
		global trans
		x = self.sect_data[self.ptr:self.ptr+n]
		if not x:
#			print 'eof'
			return None
		if rawdata == True:
			ret = self.sect_data[self.ptr:self.ptr+n]
			print self.pfx+"%-24s | %s" % (sect_name, hexlify(ret))
#			print self.pfx+"%-24s | %s..." % (sect_name, hexlify(ret[:16]))
		else:
			v = self.sect_data[self.ptr:self.ptr+n]
			if n == 1:
				ret = unpack('B', v)[0]
			elif n == 2:
				ret = unpack('>H', v)[0]
			elif n == 3:
				ret = unpack('>L', "\x00" + v)[0] 
			elif n == 4:
				ret = unpack('>L', v)[0]
			else:
				print "___GENERAL FUCKUP___"
				sys.exit(1)
			try:
				tl = self.trans[sect_name][ret]
			except KeyError:
				tl = ''
			
			self.save_kdb(sect_name, tl)
			fmtx = "0x%0" + str(n) + "x"
			print self.pfx+"%-24s | %3d | %12d | %10s | %s" % (sect_name, n, ret, fmtx % ret, tl)

#			else:
#				ret = self.response[self.ptr:self.ptr+n]
		self.ptr += n
		return ret

	def save_kdb(self, sect, val):
		if sect == 'content-type':
			self.last_ct = val
			self.last_hst = ""
		elif sect == 'handshake-type':
			self.last_hst = val
		elif self.last_ct == 'Handshake':
			if self.last_hst == 'Server-Hello':
				try: self.results[self.last_ct]
				except: self.results[self.last_ct] = {}
				try: self.results[self.last_ct][self.last_hst]
				except: self.results[self.last_ct][self.last_hst] = {}
				if sect in ["version", "cipher-suite"]:
					self.results[self.last_ct][self.last_hst][sect] = val
			else:
				pass
		else:
			pass


	def parse_response(self):
		_CONTENT_TYPE_HANDHAKE = 0x16
		_VERSION_TLS12 = 0x0303
		_VERSION_TLS11 = 0x0302
		_VERSION_TLS10 = 0x0301
		_VERSION_SSL30 = 0x0300
		_VERSION_SSL20 = 0x0002
		self.ptr = 0
		self.pfx = ''
		run = True
		while run:
			print "="*100
			ct = self.get('content-type', 1)
			if ct == None:
				print 'Finished'
				run = None
				return
#			elif ct == _CONTENT_TYPE_HANDHAKE:
#				print 'content-type: handshake (%02x)' % ct
			ver = self.get('version', 2)
#			if ver == _VERSION_TLS12:
#				print 'version: TLS1.2 (%04x)' % ver
			sect_size = self.get('length', 2)
			sect_data = self.get('section-data', sect_size, True)
			if ct == _CONTENT_TYPE_HANDHAKE:
				ptr_saved = self.ptr
				sect_data_saved = self.sect_data
#				sect_size_saved = self.sect_size
				#
				self.pfx = '\t'
				self.ptr = 0
				self.sect_data = sect_data
				#
				self.parse_handshake()
				#
				self.pfx = ''
				self.ptr = ptr_saved
				self.sect_data = sect_data_saved

	def parse_handshake(self):
		_HANDSHAKE_TYPE_SERVER_HELLO = 0x02
		_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0e
		_HANDSHAKE_TYPE_CERTIFICATE = 0x0b
		_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0c
		_VERSION_TLS12 = 0x303
		print "\t"+ ("-"*100)
		hst = self.get('handshake-type', 1)
		length = self.get('length', 3)
		# ---
		if hst == _HANDSHAKE_TYPE_SERVER_HELLO:			self.parse_hs_server_hello()
		if hst == _HANDSHAKE_TYPE_CERTIFICATE:			self.parse_hs_certificate()
		if hst == _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:	self.parse_hs_server_key_exchange()


	def parse_hs_server_key_exchange(self):
		keylen = self.get('key-length', 3)
		keydata = self.get('key-data', keylen, True)

	def parse_hs_certificate(self):
		sect_len = self.get('certificate-length', 3)
		sect_data = self.get('certificate-data', sect_len, True)
		#
		ptr_saved = self.ptr
		sect_data_saved = self.sect_data
		#
		self.pfx = '\t\t'
		self.ptr = 0
		self.sect_data = sect_data
		#
		self.parse_hs_certificate_fields()
		#
		self.pfx = ''
		self.ptr = ptr_saved
		self.sect_data = sect_data_saved
		
	def parse_hs_certificate_fields(self):		
		unknown1 = self.get('unknown-1', 7, True)
		unknown2 = self.get('unknown-2', 8, True)
		version = self.get('version', 1)
		run = True
		while run:
			f_type = self.get('f-type', 1)
			f_len = self.get('f-len', 1)
			f_val = self.get('f-val', f_len, True)


	def parse_hs_server_hello(self):
		ver = self.get('version', 2)
		ts = self.get('timestamp', 4)
		rnd = self.get('random', 28, True)
		sid_length = self.get('session-id-length', 1)
		cipher_suite = self.get('cipher-suite', 2)
		comp = self.get('compression-method', 1)
		ext_len = self.get('extensions-length', 2)
		if not ext_len:
			return
		sect_data = self.get('extensions-raw', ext_len, True)
		#
		ptr_saved = self.ptr
		sect_data_saved = self.sect_data
		#
		self.pfx = '\t\t'
		self.ptr = 0
		self.sect_data = sect_data
		#
		self.parse_extensions()
		#
		self.pfx = ''
		self.ptr = ptr_saved
		self.sect_data = sect_data_saved
		
		
	def parse_extensions(self):
		run = True
		while run:
			print "\t\t"+ (" -"*50)
			ext_type = self.get('extension-type', 2)
			if ext_type == None:
				print '\t\tFinished'
				run = None
				return
			ext_length = self.get('extension-length', 2)
			ext_raw = self.get('extension-data-raw', ext_length, True)

if __name__ == "__main__":
	host = sys.argv[1]
	port = int(sys.argv[2])
	chucky = Chucky({'host': host, 'port': port})
	chucky.hello()
	pp = pprint.PrettyPrinter(indent=4, depth=6)
	pp.pprint(chucky.results)






