#define _MAIN_CPP

#include "hash-garage/nmhash.h"
#include <cstdio>

bool nmhash32_broken( void ) {
  static bool done = false, result;
  if (done)
    return result;

  const char entropy[] = "rwgk8M1uxM6XX6c3teQX2yaw8FQWArmcWUSBJ8dcQQJWHYC9Wt2BmpvETxwhYcJTheTbjf49SVRaDJhbEZCq7ki1D6KxpKQSjgwqsiHGSgHLxvPG5kcRnBhjJ1YC8kuh";

  NMH_ALIGN(NMH_ACC_ALIGN) uint32_t accX[sizeof(NMH_ACC_INIT)/sizeof(*NMH_ACC_INIT)];
  static_assert(sizeof(entropy) >= sizeof(accX), "Need more entropy in entropy[]");
  memcpy(accX, entropy, sizeof(accX));

  const size_t nbGroups = sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT);
  size_t i;

  for (i = 0; i < nbGroups * 2; ++i) {
    ((uint16_t*)accX)[i] *= ((uint16_t*)__NMH_M1_V)[i];
  }

  // XXX: no memory barrier takes place here, just like in NMHASH32_long_round_scalar()
  // and it affects the `acc` result.

  uint32_t acc = 0;
  for (i = 0; i < nbGroups; ++i)
    acc += accX[i];

  result = (acc != UINT32_C(0x249abaee));
  done = true;
  return result;
}


int main (int argc, const char **argv)
{
  printf ("%d\n", nmhash32_broken ());
  return 0;
}
