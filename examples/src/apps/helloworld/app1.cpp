#include <stdio.h>
#include <stdint.h>

#include "common.h"


extern "C"
LIB_EXPORT
int checkVer(const uint8_t *data_ver_str, uint32_t size_str)
{
  if (size_str != 3)
    return -3;
  if (data_ver_str[2] % 2 != 0)
    return -1;
  if (data_ver_str[2] < 1 || data_ver_str[2] > 7)
    return -2;
  return 0;
}

#ifdef CONFIG_DBG_MAIN
int main(int argc, char *argv[])
{
  // expected: -3
  printf("INPUT[1]:%d\n", checkVer((const uint8_t *)"\x00\x00", 2));
  
  // expected: -3
  printf("INPUT[2]:%d\n", checkVer((const uint8_t *)"\x00\x00\x00\x00", 4));
  
  // expected: 0
  printf("INPUT[3]:%d\n", checkVer((const uint8_t *)"\x00\x00\x06", 3));
  
  // expected: -1
  printf("INPUT[4]:%d\n", checkVer((const uint8_t *)"\x00\x00\x05", 3));
  
  // *** discrepancy ***
  // expected: 0
  printf("INPUT[5]:%d\n", checkVer((const uint8_t *)"\x00\x00\x02", 3));
  
  return 0;
}
#endif
