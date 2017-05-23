# libreSSL 2.4.0

### Brief
LibreSSL ignores the tag in the `Time` ASN.1 structure, and tries to infer the
type of the `Time` (`UTCTime` or `GeneralizedTime`) based on the length of the
structure. 

When the `Time` structure in the `GeneralizedTime` form does not 
take the assumed form of `YYYYMMDDHHMMSSZ`, but instead is of the form 
`YYYYMMDDHHMMZ`, LibreSSL treats the `GeneralizedTime` as `UTCTime`.


### Impact
There are two possibilities when this problem manifests in the different time 
fields within the `Validity` structure.

`notBefore`:  LibreSSL may erroneously treat a valid certificate as not yet
valid, when in fact it is valid.

`notAfter`: LibreSSL may erroneously accept an expired certificate. This is a
more dangerous consequence.


### Error Codes

OpenSSL: ACCEPT / `ERR_CERT_HAS_EXPIRED`

LibreSSL: `ERR_CERT_NOT_YET_VALID` / ACCEPT

BoringSSL: ACCEPT / `ERR_CERT_HAS_EXPIRED`


### Structure of Interest
The time fields in the `Validity` struct
```
Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time  }
Time ::= CHOICE {
     utcTime        UTCTime,
     generalTime    GeneralizedTime }
```


### Driver Dump

####Driver
 cmd:./test_openssl 1_libressl_9010_0689e3080ef6eedb9fee46e0bf9ed8fe__MIN 

######stdout:
```
- cert offset[1]: 0
- cert offset[2]: 1448
- cert offset[3]: 2888
- cert offset[4]: 3494
[OSSL] [cert:0x0x62000000f080  sz:3494] ret=1  depth=0  err=0
openssl: 	1 (ok)
```

####Driver
 cmd:./test_libressl 1_libressl_9010_0689e3080ef6eedb9fee46e0bf9ed8fe__MIN 

######stdout:
```
- cert offset[1]: 0
- cert offset[2]: 1448
- cert offset[3]: 2888
- cert offset[4]: 3494
[LSSL] [cert:0x0x62000000f080  sz:3494] ret=0  depth=1  err=9
140194457839264:error:04091068:lib(4):func(145):reason(104):rsa/rsa_sign.c:232:
libressl: 	9010 
```


POC
===

### Rejecting a valid certificate

OpenSSL (and BoringSSL) accepts this certificate.
```
$ ./openssl x509 -noout -text -in cert_notBefore_valid.pem
...
        Validity
            Not Before: Jan  1 01:01:00 2012 GMT
            Not After : Jun 28 09:16:46 2018 GMT
            (... snip ...)

$ ./openssl asn1parse -in cert_notBefore_valid.pem
...
  106:d=3  hl=2 l=  13 prim: GENERALIZEDTIME   :201201010101Z
  121:d=3  hl=2 l=  13 prim: UTCTIME           :180628091646Z
  (... snip ...)

$ ./openssl verify -CApath certs/CApath cert_notBefore_valid.pem 
cert_notBefore_valid.pem: OK
```

LibreSSL erroneously rejects this valid certificate.
```
$ ./libressl verify -CAfile certs/CApath/c1769900.0 cert_notBefore_valid.pem 
cert_notBefore_valid.pem: CN = Intermediate CA, ST = Some-State, C = AU, O = Intermediate CA
error 9 at 0 depth lookup:certificate is not yet valid
```


### Accepting an expired certificate

OpenSSL (and BoringSSL) rejects this certificate as expired.
```
$ ./openssl x509 -noout -text -in cert_notAfter_expired.pem
...
        Validity
            Not Before: Jan  1 01:01:01 2011 GMT
            Not After : Jan  1 01:01:00 2012 GMT
            (... snip ...)

$ ./openssl asn1parse -in cert_notAfter_expired.pem
...
  106:d=3  hl=2 l=  13 prim: UTCTIME           :110101010101Z
  121:d=3  hl=2 l=  13 prim: GENERALIZEDTIME   :201201010101Z
  (... snip ...)

$ ./openssl verify -CApath certs/CApath cert_notAfter_expired.pem 
cert_notAfter_expired.pem: CN = Intermediate CA, ST = Some-State, C = AU, O = Intermediate CA
error 10 at 0 depth lookup:certificate has expired
OK
```

LibreSSL erroneously accepts this expired certificate.
```
$ ./libressl verify -CAfile certs/CApath/c1769900.0 cert_notAfter_expired.pem
cert_notAfter_expired.pem: OK
```



### Analysis
LibreSSL infers the type of time format based on the length of the `Time` ASN.1
structure as follows:
```
[crypto/x509/x509_vfy.c]
int
X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
{
	...
	if ((type = asn1_time_parse(ctm->data, ctm->length, &tm1, 0)) == -1)
		goto out; /* invalid time */

[crypto/asn1/a_time_tm.c]
int
asn1_time_parse(const char *bytes, size_t len, struct tm *tm, int mode)
{
	...
	int type = 0;
	...
	/* Constrain to valid lengths. */
	if (len != UTCTIME_LENGTH && len != GENTIME_LENGTH)
		return (-1);
	...
	switch (len) {
	case GENTIME_LENGTH:
		...
	case UTCTIME_LENGTH:
		if (type == 0) {
			if (mode == V_ASN1_GENERALIZEDTIME)
				return (-1);
			type = V_ASN1_UTCTIME;
		}
		...
	return (type);
```

In cases where a `GeneralizedTime` time can be properly parsed as `UTCTime`, 
the `X509_cmp_time()` proceeds to use this time in its comparison.
```
[crypto/x509/x509_vfy.c]
int
X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
{
	...
	if ((type = asn1_time_parse(ctm->data, ctm->length, &tm1, 0)) == -1)
		goto out; /* invalid time */
	...
	ret = asn1_tm_cmp(&tm1, &tm2);
	if (ret == 0)
		ret = -1; /* 0 is used for error, so map same to less than */
 out:
	return (ret);
```