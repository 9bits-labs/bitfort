// The interposer `check-heap-wipe.sh` loads into `bitfort` through DYLD_INSERT_LIBRARIES
// (macOS). It counts every `free`, and every freed block that still holds one of the markers in
// FREEWATCH_HEX: comma-separated hex, so that no marker is itself in the environment. `realloc`
// is done as malloc + copy + free, so the old copy that a moving reallocation leaves behind is
// checked too. The counts go to stderr at exit as `FREEWATCH frees=N hits=A,B,...`.
#include <malloc/malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DYLD_INTERPOSE(replacement, replacee)                                          \
  __attribute__((used)) static struct {                                                \
    const void *with;                                                                  \
    const void *what;                                                                  \
  } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {            \
      (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&replacee};

#define MAX_MARKERS 4
static char markers[MAX_MARKERS][64];
static size_t lens[MAX_MARKERS];
static int count;
static unsigned long hits[MAX_MARKERS];
static unsigned long frees;

static int nibble(char c) {
  return c >= 'a' ? c - 'a' + 10 : c - '0';
}

__attribute__((constructor)) static void setup(void) {
  const char *hex = getenv("FREEWATCH_HEX");
  while (hex && *hex && count < MAX_MARKERS) {
    size_t n = 0;
    while (hex[0] && hex[0] != ',' && hex[1] && n < sizeof markers[0]) {
      markers[count][n++] = (char)(nibble(hex[0]) << 4 | nibble(hex[1]));
      hex += 2;
    }
    lens[count++] = n;
    if (*hex == ',') hex++;
  }
}

static void watch_free(void *p) {
  if (p) {
    __atomic_fetch_add(&frees, 1, __ATOMIC_RELAXED);
    size_t n = malloc_size(p);
    for (int i = 0; i < count; i++)
      if (memmem(p, n, markers[i], lens[i])) __atomic_fetch_add(&hits[i], 1, __ATOMIC_RELAXED);
  }
  free(p);
}

static void *watch_realloc(void *p, size_t size) {
  if (!p) return malloc(size);
  size_t old = malloc_size(p);
  void *moved = malloc(size ? size : 1);
  if (!moved) return NULL;
  memcpy(moved, p, old < size ? old : size);
  watch_free(p);
  return moved;
}

DYLD_INTERPOSE(watch_free, free)
DYLD_INTERPOSE(watch_realloc, realloc)

__attribute__((destructor)) static void report(void) {
  char buf[256];
  int len = snprintf(buf, sizeof buf, "FREEWATCH frees=%lu hits=", frees);
  for (int i = 0; i < count; i++)
    len += snprintf(buf + len, sizeof buf - (size_t)len, i ? ",%lu" : "%lu", hits[i]);
  len += snprintf(buf + len, sizeof buf - (size_t)len, "\n");
  write(2, buf, (size_t)len);
}
