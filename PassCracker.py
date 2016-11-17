#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'leohuang'
__date__ = '2016/11/16'
__version__ = '0.1-dev'

from hashid import *
from hashdecrypt import *



"""
# print support detect algorithms
al_dict = algorithms
for hs in sorted(al_dict):
    print('    "%s":"%s",' %(hs, algorithms[hs]) )
#"""

def detect_hash(hash):
    jerar=[]
    ADLER32(hash, jerar); CRC16(hash, jerar); CRC16CCITT(hash, jerar); CRC32(hash, jerar); CRC32B(hash, jerar); DESUnix(hash, jerar); DomainCachedCredentials(hash, jerar); FCS16(hash, jerar); GHash323(hash, jerar); GHash325(hash, jerar); GOSTR341194(hash, jerar); Haval128(hash, jerar); Haval128HMAC(hash, jerar); Haval160(hash, jerar); Haval160HMAC(hash, jerar); Haval192(hash, jerar); Haval192HMAC(hash, jerar); Haval224(hash, jerar); Haval224HMAC(hash, jerar); Haval256(hash, jerar); Haval256HMAC(hash, jerar); LineageIIC4(hash, jerar); MD2(hash, jerar); MD2HMAC(hash, jerar); MD4(hash, jerar); MD4HMAC(hash, jerar); MD5(hash, jerar); MD5APR(hash, jerar); MD5HMAC(hash, jerar); MD5HMACWordpress(hash, jerar); MD5phpBB3(hash, jerar); MD5Unix(hash, jerar); MD5Wordpress(hash, jerar); MD5Half(hash, jerar); MD5Middle(hash, jerar); MD5passsaltjoomla1(hash, jerar); MD5passsaltjoomla2(hash, jerar); MySQL(hash, jerar); MySQL5(hash, jerar); MySQL160bit(hash, jerar); NTLM(hash, jerar); RAdminv2x(hash, jerar); RipeMD128(hash, jerar); RipeMD128HMAC(hash, jerar); RipeMD160(hash, jerar); RipeMD160HMAC(hash, jerar); RipeMD256(hash, jerar); RipeMD256HMAC(hash, jerar); RipeMD320(hash, jerar); RipeMD320HMAC(hash, jerar); SAM(hash, jerar); SHA1(hash, jerar); SHA1Django(hash, jerar); SHA1HMAC(hash, jerar); SHA1MaNGOS(hash, jerar); SHA1MaNGOS2(hash, jerar); SHA224(hash, jerar); SHA224HMAC(hash, jerar); SHA256(hash, jerar); SHA256s(hash, jerar); SHA256Django(hash, jerar); SHA256HMAC(hash, jerar); SHA256md5pass(hash, jerar); SHA256sha1pass(hash, jerar); SHA384(hash, jerar); SHA384Django(hash, jerar); SHA384HMAC(hash, jerar); SHA512(hash, jerar); SHA512HMAC(hash, jerar); SNEFRU128(hash, jerar); SNEFRU128HMAC(hash, jerar); SNEFRU256(hash, jerar); SNEFRU256HMAC(hash, jerar); Tiger128(hash, jerar); Tiger128HMAC(hash, jerar); Tiger160(hash, jerar); Tiger160HMAC(hash, jerar); Tiger192(hash, jerar); Tiger192HMAC(hash, jerar); Whirlpool(hash, jerar); WhirlpoolHMAC(hash, jerar); XOR32(hash, jerar); md5passsalt(hash, jerar); md5saltmd5pass(hash, jerar); md5saltpass(hash, jerar); md5saltpasssalt(hash, jerar); md5saltpassusername(hash, jerar); md5saltmd5pass(hash, jerar); md5saltmd5passsalt(hash, jerar); md5saltmd5passsalt(hash, jerar); md5saltmd5saltpass(hash, jerar); md5saltmd5md5passsalt(hash, jerar); md5username0pass(hash, jerar); md5usernameLFpass(hash, jerar); md5usernamemd5passsalt(hash, jerar); md5md5pass(hash, jerar); md5md5passsalt(hash, jerar); md5md5passmd5salt(hash, jerar); md5md5saltpass(hash, jerar); md5md5saltmd5pass(hash, jerar); md5md5usernamepasssalt(hash, jerar); md5md5md5pass(hash, jerar); md5md5md5md5pass(hash, jerar); md5md5md5md5md5pass(hash, jerar); md5sha1pass(hash, jerar); md5sha1md5pass(hash, jerar); md5sha1md5sha1pass(hash, jerar); md5strtouppermd5pass(hash, jerar); sha1passsalt(hash, jerar); sha1saltpass(hash, jerar); sha1saltmd5pass(hash, jerar); sha1saltmd5passsalt(hash, jerar); sha1saltsha1pass(hash, jerar); sha1saltsha1saltsha1pass(hash, jerar); sha1usernamepass(hash, jerar); sha1usernamepasssalt(hash, jerar); sha1md5pass(hash, jerar); sha1md5passsalt(hash, jerar); sha1md5sha1pass(hash, jerar); sha1sha1pass(hash, jerar); sha1sha1passsalt(hash, jerar); sha1sha1passsubstrpass03(hash, jerar); sha1sha1saltpass(hash, jerar); sha1sha1sha1pass(hash, jerar); sha1strtolowerusernamepass(hash, jerar);

    jerar.sort()
    return jerar

if __name__ == '__main__':
    pass_type_list = []
    hash = "e10adc3949ba59abbe56e057f20f883e"
    hash = "CBB5199C8E931F069E7E77EA8947E0D8"
    #hash = '7c4a8d09ca3762af61e59520943dc26494f8941b'
    pass_type_list = detect_hash(hash)
    flag = False

    print("Crack Hash:%s" %(hash) )
    if pass_type_list:
        for pass_type in pass_type_list:
            if pass_type not in decrpt_algorithms:
                #print("[-]No Crack algorithms: %s" %(algorithms[pass_type]))
                pass
            else:
                flag = hash_decrypt(hash, pass_type)
                if flag: break

    else:
        print("Not Found this hash: %s" %(hash))

