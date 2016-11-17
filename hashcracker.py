#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'leohuang'
__date__ = '2016/11/16'
__version__ = '0.1-dev'

from passlib.hash import nthash
import hashlib

# 支持破解的类型。值和名称必须与hashid匹配
decrpt_algorithms = {
    "101020":"CRC-16",
    "101040":"CRC-16-CCITT",
    "101060":"FCS-16",
    "102020":"ADLER-32",
    "102040":"CRC-32",
    "102060":"CRC-32B",
    "102080":"XOR-32",
    "103020":"GHash-32-5",
    "103040":"GHash-32-3",
    "104020":"DES(Unix)",
    "105020":"MySQL",
    "105040":"MD5(Middle)",
    "105060":"MD5(Half)",
    "106020":"MD5",
    "106027":"RAdmin v2.x",
    "106029":"NTLM",
    "106040":"MD4",
    "106060":"MD2",
    "106080":"MD5(HMAC)",
    "106100":"MD4(HMAC)",
    "106120":"MD2(HMAC)",
    "106140":"MD5(HMAC(Wordpress))",
    "106160":"Haval-128",
    "106165":"Haval-128(HMAC)",
    "106180":"RipeMD-128",
    "106185":"RipeMD-128(HMAC)",
    "106200":"SNEFRU-128",
    "106205":"SNEFRU-128(HMAC)",
    "106220":"Tiger-128",
    "106225":"Tiger-128(HMAC)",
    "106500":"md5(md5($pass))",
    "107060":"MD5(Unix)",
    "107080":"Lineage II C4",
    "108020":"MD5(APR)",
    "109020":"SHA-1",
    "109040":"MySQL5 - SHA-1(SHA-1($pass))",
    "109060":"MySQL 160bit - SHA-1(SHA-1($pass))",
    "109080":"Tiger-160",
    "109100":"Haval-160",
    "109120":"RipeMD-160",
    "109140":"SHA-1(HMAC)",
    "109160":"Tiger-160(HMAC)",
    "109180":"RipeMD-160(HMAC)",
    "109200":"Haval-160(HMAC)",
    "109220":"SHA-1(MaNGOS)",
    "109240":"SHA-1(MaNGOS2)",
    "1094202":"sha1(md5($pass))",
    "109460":"sha1(md5(sha1($pass)))",
    "109480":"sha1(sha1($pass))",
    "109520":"sha1(sha1($pass).substr($pass,0,3))",
    "109560":"sha1(sha1(sha1($pass)))",
    "110020":"Tiger-192",
    "110040":"Haval-192",
    "110060":"Tiger-192(HMAC)",
    "110080":"Haval-192(HMAC)",
    "113020":"SHA-1(Django)",
    "114020":"SHA-224",
    "114040":"Haval-224",
    "114060":"SHA-224(HMAC)",
    "114080":"Haval-224(HMAC)",
    "115020":"SHA-256",
    "115040":"Haval-256",
    "115060":"GOST R 34.11-94",
    "115080":"RipeMD-256",
    "115100":"SNEFRU-256",
    "115120":"SHA-256(HMAC)",
    "115140":"Haval-256(HMAC)",
    "115160":"RipeMD-256(HMAC)",
    "115180":"SNEFRU-256(HMAC)",
    "115200":"SHA-256(md5($pass))",
    "115220":"SHA-256(sha1($pass))",
    "116040":"SAM - (LM_hash:NT_hash)",
    "117020":"SHA-256(Django)",
    "118020":"RipeMD-320",
    "118040":"RipeMD-320(HMAC)",
    "119020":"SHA-384",
    "119040":"SHA-384(HMAC)",
    "120020":"SHA-256",
    "121020":"SHA-384(Django)",
    "122020":"SHA-512",
    "122040":"Whirlpool",
    "122060":"SHA-512(HMAC)",
    "122080":"Whirlpool(HMAC)",
}

dict_file = "dict/password.txt"

def md5_decrypt(hash):
    hash = hash.upper()
    with open(dict_file) as f:
        for pwd in f.readlines():
            pwd = pwd.strip()
            epwd = hashlib.md5(pwd.encode(encoding='utf-8')).hexdigest().upper()
            if epwd == hash:
                return [True, pwd]
    return [False,""]

def sha1_decrypt(hash):
    hash = hash.upper()
    with open(dict_file) as f:
        for pwd in f.readlines():
            pwd = pwd.strip()
            epwd = hashlib.sha1(pwd.encode(encoding='utf-8')).hexdigest().upper()
            if epwd == hash:
                return [True, pwd]
    return [False,""]

def ntlm_decrypt(hash):
    hash = hash.upper()
    with open(dict_file) as f:
        for pwd in f.readlines():
            pwd = pwd.strip()
            epwd = nthash.encrypt(pwd).upper()
            if epwd == hash:
                return [True, pwd]

    return [False,""]

def hash_decrypt(hash, pass_type):
    type_name = decrpt_algorithms[pass_type]
    #print("[-]Crack Type: %s | Hash:%s" %(type_name ,hash) )
    print("[-]Crack Type: %s" %(type_name) )
    flag = False
    if type_name == "MD5":
        flag, pwd = md5_decrypt(hash)
    elif type_name == "NTLM":
        flag, pwd = ntlm_decrypt(hash)
    elif type_name == "SHA-1":
        flag, pwd = sha1_decrypt(hash)
    else:
        #print("[-]Not support crack hash type: %s" %(pass_type) )
        pass

    if flag:
        print("[!]Crack OK:%s" %(pwd) )

    return flag

if __name__ == '__main__':
    hash = "e10adc3949ba59abbe56e057f20f883e"
    pass_type = "106020"
    hash_decrypt(hash, pass_type)

    hash = "CBB5199C8E931F069E7E77EA8947E0D8"
    pass_type = "106029"
    hash_decrypt(hash, pass_type)

