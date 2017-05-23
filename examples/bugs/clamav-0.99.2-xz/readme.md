### Brief

XZutils can decompress a mutated archive, but ClamAV detects that archive as 
malformed and thus does not attempt to scan it.

### Impact

Critical/High: An attacker can craft a malicious XZ archive that can decompress
properly using XZUtils and yet evade the scanning of ClamAV.


### Structure of Interest 

The structure of interest is the `Dictionary Size` byte that describes the size
of the variable compression dictionary buffer used for the LZMA2 decompression.

Changing the byte at offset `0x10` to the value between `0x1F` and `0x40` 
inclusive will trigger the parsing failure of the ClamAV XZ parsing engine.


### Driver Test
```
$ ./test_clamav eicar.evade.xz 
clamav:26:CL_EFORMAT: Bad format or broken data

$ ./test_xzutils eicar.evade.xz 
xzutils:0:OK
```

### POC
```
$ xz -l eicar.orig.xz
Strms  Blocks   Compressed Uncompressed  Ratio  Check   Filename
    1       1        252 B     10.0 KiB  0.025  CRC64   eicar.orig.xz

$ ./clamscan --debug eicar.orig.xz
...
LibClamAV debug: Recognized XZ container file file
...
LibClamAV debug: Eicar-Test-Signature found
...
Infected files: 1
...

$ ./clamscan --debug eicar.evade.xz
...
LibClamAV debug: Recognized XZ container file file
...
LibClamAV Error: cli_scanxz: decompress error: 1
...
Infected files: 0
...

$ tar xf eicar.evade.xz && cat eicar.com.txt
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```


### Analysis
When the LZMA2 compression filter is used in the decompression blocks, the 
one-byte filter flag in the block header specifies the size of the dictionary
buffer to allocate for the decompression process.

According to the reference format at http://tukaani.org/xz/xz-file-format.txt, 
a rough pseudocode is given to decode the dictionary size.

```
Dictionary Size is encoded with one-bit mantissa and five-bit exponent. The 
smallest dictionary size is 4 KiB and the biggest is 4 GiB.

    const uint8_t bits = get_dictionary_flags() & 0x3F;
    if (bits > 40)
        return DICTIONARY_TOO_BIG; // Bigger than 4 GiB

    uint32_t dictionary_size;
    if (bits == 40) {
        dictionary_size = UINT32_MAX;
    } else {
        dictionary_size = 2 | (bits & 1);
        dictionary_size <<= bits / 2 + 11;
    }
```

ClamAV XZ engine does exactly as recommended by the standards. The relevant 
code is as follows:

```
[libclamav/7z/XzDec.c]
SRes XzDec_Init(CMixCoder *p, const CXzBlock *block)
{
  
  ...
  for (i = 0; i < numFilters; i++)
  {
    const CXzFilter *f = &block->filters[numFilters - 1 - i];
    IStateCoder *sc = &p->coders[i];
    RINOK(sc->SetProps(sc->p, f->props, f->propsSize, p->alloc));
  }
  ...

static SRes Lzma2State_SetProps(void *pp, const Byte *props, size_t propSize, ISzAlloc *alloc)
{
  ...
  return Lzma2Dec_Allocate((CLzma2Dec *)pp, props[0], alloc);
}


[7z/Lzma2Dec.c]
SRes Lzma2Dec_Allocate(CLzma2Dec *p, Byte prop, ISzAlloc *alloc)
{
  Byte props[LZMA_PROPS_SIZE];
  RINOK(Lzma2Dec_GetOldProps(prop, props));
  return LzmaDec_Allocate(&p->decoder, props, LZMA_PROPS_SIZE, alloc);
  ...

static SRes Lzma2Dec_GetOldProps(Byte prop, Byte *props)
{
  UInt32 dicSize;
  if (prop > 40)
    return SZ_ERROR_UNSUPPORTED;
  dicSize = (prop == 40) ? 0xFFFFFFFF : LZMA2_DIC_SIZE_FROM_PROP(prop);
  props[0] = (Byte)LZMA2_LCLP_MAX;
  props[1] = (Byte)(dicSize);
  props[2] = (Byte)(dicSize >> 8);
  props[3] = (Byte)(dicSize >> 16);
  props[4] = (Byte)(dicSize >> 24);
  return SZ_OK;
}
```

This dictionary size, `dicSize`, is subsequently used in the allocation of
the temp buffer for the dictionary.

```
[libclamav/7z/LzmaDec.c]
SRes LzmaDec_Allocate(CLzmaDec *p, const Byte *props, unsigned propsSize, ISzAlloc *alloc)
{
  CLzmaProps propNew;
  SizeT dicBufSize;
  
  RINOK(LzmaProps_Decode(&propNew, props, propsSize));
  RINOK(LzmaDec_AllocateProbs2(p, &propNew, alloc));
  
  dicBufSize = propNew.dicSize;
  if (p->dic == 0 || dicBufSize != p->dicBufSize)
  {
    LzmaDec_FreeDict(p, alloc);
    p->dic = (Byte *)alloc->Alloc(alloc, dicBufSize);
    if (p->dic == 0)
    {
      LzmaDec_FreeProbs(p, alloc);
      return SZ_ERROR_MEM;
    }
  ...
```

The allocation function in `xz_iface.c` fails when the intended allocation size 
is more than 182MiB. This severely underestimates the maximum dictionary size 
allowed by the standards.

```
[libclamav/xz_iface.c]
void *__xz_wrap_alloc(void *unused, size_t size) {
    
    // #define CLI_MAX_ALLOCATION  (182*1024*1024)
    if(!size || size > CLI_MAX_ALLOCATION)
      return NULL;
      ...
```

This more restrictive check within ClamAV is harmless in itself. However, the 
defacto XZ parsing tool, XZUtils, on most Linux systems is more permissive in
this respect. In other words, it conforms to the standards closely and does
not have the same restrictions as ClamAV. 

As a result, XZUtils can successfully decompresses an XZ archive even if the 
dictionary size is more than 182 Mib (and less than 4 Gib). The relevant code 
within XZUtils is as follows:

```
[xztuils/src/liblzma/lzma/lzma2_decoder.c]
extern lzma_ret
lzma_lzma2_props_decode(...)
{
	if (props_size != 1)
		return LZMA_OPTIONS_ERROR;

	// Check that reserved bits are unset.
	if (props[0] & 0xC0)
		return LZMA_OPTIONS_ERROR;

	// Decode the dictionary size.
	if (props[0] > 40)
		return LZMA_OPTIONS_ERROR;

	lzma_options_lzma *opt = lzma_alloc(
			sizeof(lzma_options_lzma), allocator);
	if (opt == NULL)
		return LZMA_MEM_ERROR;

	if (props[0] == 40) {
		opt->dict_size = UINT32_MAX;
	} else {
		opt->dict_size = 2 | (props[0] & 1);
		opt->dict_size <<= props[0] / 2 + 11;
	}

	opt->preset_dict = NULL;
	opt->preset_dict_size = 0;

	*options = opt;
    ...


[xztuils/src/liblzma/lzma/lzma_decoder.c.c]
extern lzma_ret
lzma_lzma_decoder_create(...)
{
    ...
	// All dictionary sizes are OK here. LZ decoder will take care of
	// the special cases.
	const lzma_options_lzma *options = opt;
	lz_options->dict_size = options->dict_size;


[xztuils/src/liblzma/lz/lz_decoder.c]
extern lzma_ret
lzma_lz_decoder_init(...)
{
    ...
	// Allocate and initialize the dictionary.
	if (next->coder->dict.size != lz_options.dict_size) {
		lzma_free(next->coder->dict.buf, allocator);
		next->coder->dict.buf
				= lzma_alloc(lz_options.dict_size, allocator);
		if (next->coder->dict.buf == NULL)
			return LZMA_MEM_ERROR;


[xztuils/src/liblzma/common/common.c]
lzma_alloc(size_t size, const lzma_allocator *allocator)
{
	// Some malloc() variants return NULL if called with size == 0.
	if (size == 0)
		size = 1;

	void *ptr;

	if (allocator != NULL && allocator->alloc != NULL)
		ptr = allocator->alloc(allocator->opaque, 1, size);
	else
		ptr = malloc(size);
```

This discrepancy in the treatment of the dictionary size in an XZ archive 
across XZUtils and ClamAV gives rise to the possibility that a malicious XZ
archive can be crafted to evade the detection of ClamAV scanning.
