# Info

Finds parsing bug in Time ASN.1 for libreSSL 2.4.0

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


# POC
## Installation
From the top directory run
```
openssl-1.0.2h_libressl-2.4.0/build.sh
```

## Invoking the bug
Verify with the independent drivers

```
$ ./test_openssl.der cert_notAfter_expired.der
openssl:a000:certificate has expired
$ ./test_libressl.der cert_notAfter_expired.der
libressl:0:OK
```

Alternatively, start a dummy fuzzy session via
```
make test
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
### Error Codes

OpenSSL: ACCEPT / `ERR_CERT_HAS_EXPIRED`
LibreSSL: `ERR_CERT_NOT_YET_VALID` / ACCEPT


