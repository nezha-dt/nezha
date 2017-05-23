# BoringSSL - commit f0451ca3

### Brief
This bug only manifests itself in chain with more than one certificate.

BoringSSL fails to parse the `X509v3 Key Usage` correctly when the padding byte 
of the Key Usage OCTET STRING is more than 8 and thus interprets a
CA cert as being invalid. Conversely, LibreSSL successfully parses the 
structure.

### Error Codes
LibreSSL: ACCEPT
BoringSSL: `ERR_INVALID_CA`


Structure of Interest
=====================
`X509v3 Key Usage` (Offset 1603)


Driver Dump
===========

##Library: boringssl

####Driver
 cmd:./test_boringssl 18010_0_18010_0ad0a_35a97_76046_348_5da2155b41f6f9430205d35e1580f3da 


######stdout:
```
- cert offset[1]: 0
- cert offset[2]: 1066
- cert offset[3]: 1997
[OSSL] [cert:0x0x61f00000ee80  sz:2978] ret=0  depth=1  err=24
openssl: 	18010 
```


##Library: libressl

####Driver
 cmd:./test_libressl 18010_0_18010_0ad0a_35a97_76046_348_5da2155b41f6f9430205d35e1580f3da 

######stdout:
```
- cert offset[1]: 0
- cert offset[2]: 1066
- cert offset[3]: 1997
[LSSL] [cert:0x0x61f00000ee80  sz:2978] ret=1  depth=0  err=0
libressl: 	1 (ok)
```


POC
===

### OpenSSL: Parsing failure
```
$ openssl/openssl x509 -noout -text -inform der -in cert_mutate.der 
...
    X509v3 Key Usage: critical
        .. .
```

### LibreSSL: Parsing success
```
$ libressl/openssl x509 -noout -text -inform der -in cert_mutate.der 
...
    X509v3 Key Usage: critical
        Digital Signature, Certificate Sign, CRL Sign
```
