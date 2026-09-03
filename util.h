#ifndef ZELDA3_UTIL_H_
#define ZELDA3_UTIL_H_

#include "types.h"

typedef struct SDL_Window SDL_Window;

struct RendererFuncs {
  bool (*Initialize)(SDL_Window *window);
  void (*Destroy)();
  void (*BeginDraw)(int width, int height, uint8 **pixels, int *pitch);
  void (*EndDraw)();
};


typedef struct ByteArray {
  uint8 *data;
  size_t size, capacity;
} ByteArray;

// ByteArray grows with realloc, so it is desktop-only; the embedded target has
// no allocator and compiles util.c with -DHEADLESS.
#ifndef HEADLESS
void ByteArray_Resize(ByteArray *arr, size_t new_size);
void ByteArray_Destroy(ByteArray *arr);
void ByteArray_AppendData(ByteArray *arr, const uint8 *data, size_t data_size);
void ByteArray_AppendByte(ByteArray *arr, uint8 v);
#endif

// Not built for the embedded target, which has no allocator: the Game & Watch
// port compiles util.c with -DHEADLESS and never calls this. The desktop build
// needs it in main.c, config.c and glsl_shader.c.
#ifndef HEADLESS
uint8 *ReadWholeFile(const char *name, size_t *length);
#endif
char *NextDelim(char **s, int sep);
char *NextLineStripComments(char **s);
char *NextPossiblyQuotedString(char **s);
char *SplitKeyValue(char *p);
bool StringEqualsNoCase(const char *a, const char *b);
const char *StringStartsWithNoCase(const char *a, const char *b);
bool ParseBool(const char *value, bool *result);
const char *SkipPrefix(const char *big, const char *little);
void StrSet(char **rv, const char *s);
char *StrFmt(const char *fmt, ...);
#ifndef HEADLESS
char *ReplaceFilenameWithNewPath(const char *old_path, const char *new_path);
#endif

#endif  // ZELDA3_UTIL_H_