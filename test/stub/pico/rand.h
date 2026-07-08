#ifndef STUB_PICO_RAND_H
#define STUB_PICO_RAND_H

/*
 * Host stub for the Pico SDK's <pico/rand.h>.
 * On real hardware get_rand_64() is the RP2040's ROSC-backed RNG; on the
 * host each test harness provides its own deterministic definition so that
 * secret generation is reproducible.
 */

#include <stdint.h>

uint64_t get_rand_64(void); /* provided by the host harness */

#endif
