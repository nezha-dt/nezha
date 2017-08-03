#include <stdio.h>
#include <stdint.h>
#include <stddef.h>


int FuzzMe(const uint8_t *Data,
            size_t DataSize) {
  return DataSize >= 3 && Data[0] == 'F';
}

int FuzzMeToo(const uint8_t *Data,
               size_t DataSize) {
  return DataSize >= 3 &&
      Data[0] == 'F' &&
      Data[1] == 'U' &&
      Data[2] == 'Z' &&
      Data[3] == 'Z';  // :‑<
}

typedef int (*UserCallback)(const uint8_t *Data, size_t Size);
struct UserCallbacks {
  UserCallback *callbacks;
  int size;
} callback_cont = { NULL, 0 };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return FuzzMe(Data, Size);
}

extern "C" int Callback2(const uint8_t *Data, size_t Size) {
  return FuzzMeToo(Data, Size);
}

UserCallback gl_callbacks[2] = { LLVMFuzzerTestOneInput, Callback2 };
extern "C" UserCallbacks *LLVMFuzzerCustomCallbacks() {
  callback_cont.callbacks = gl_callbacks;
  callback_cont.size = 2;
  return &callback_cont;
}

