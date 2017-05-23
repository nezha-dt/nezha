/* unzp.cpp v1.00 -- A simple program to decompress a ZPAQ archive.

  Copyright (C) 2011, Dell Inc. Written by Matt Mahoney.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so without restriction.
  This Software is provided "as is" without warranty.

Usage: unzp input.zpaq output

unzp decompresses input.zpaq to output. It ignores stored filenames, comments,
and checksums. If input.zpaq contains more than one file, then all of the
compressed contents are concatenated.

To compile for x86-32 or x86-64 processors supporting SSE2 under Windows
or Linux:


Create:
zpaq a test.zpaq test.txt

Comipile:
g++ -O3 libzpaqdriver.cpp libzpaq.cpp -o libzpaqdriver -lcrypto

For all other targets, use option -DNOJIT (will run slower).
*/

#include "libzpaq.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#define  LENGTH 4096

// Required implementation of error handler.
// msg will be an English description of the error. It should not return.
// Any attempt to decompress the rest of the block will likely fail,
// but skipping to the start of the next block would be OK.
void libzpaq::error(const char* msg) {
  fprintf(stderr, "unzp error: %s\n", msg);
  exit(1);
}

// Required implementations of
// int libzpaq::Reader::get() and
// void libzpaq::Writer::put(int c)
// for reading and writing byte strings or files.
struct File: public libzpaq::Reader, public libzpaq::Writer {
  FILE* f;
  int get() {return getc(f);}   // read and return byte 0..255, or -1 at EOF
  void put(int c) {putc(c, f);} // write byte c (0..255)
};

int main(int argc, char** argv) {

  // Check for 2 filename arguments
  if (argc!=2)
    return fprintf(stderr, "To decompress: unzp input.zpaq\n"), 1;

  // Open files
  File in, out;
  FILE *tmp;
  int i;
  char buf[LENGTH];
  unsigned char result[MD5_DIGEST_LENGTH];
 
  int c;  

  in.f=fopen(argv[1], "rb");
  if (!in.f) return perror(argv[1]), 1;
  out.f=fopen("tmp.txt", "wb+");
  if (!out.f) return perror(argv[2]), 1;

  // Decompress
  libzpaq::decompress(&in, &out);



 
 fseek (out.f, 0, SEEK_END);
 int  size = ftell(out.f);

  if (size == 0) {
      printf("file is empty\n");
  }while ((c = getc(out.f)) != EOF);


 tmp = fopen("tmp.txt","rb");
 size_t newLen = fread(buf, sizeof(char), LENGTH-1, tmp);
  
  
  if (ferror(out.f) != 0) {
        fputs("Error reading file", stderr);
    } else {
        buf[newLen++] = '\0'; /* Just to be safe. */
    }
    MD5((unsigned char*)&buf, strlen(buf), (unsigned char*)result);  
    for(i=0; i <MD5_DIGEST_LENGTH; i++) {
          printf("%02x",result[i]);
  }
  printf("\n"); 
  fclose(tmp);	
  return 0;
} 