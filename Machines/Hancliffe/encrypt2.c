#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
	_Bool b;
  int i;
  int length;
  char c;
  char* s;

  s = argv[1];
	length = strlen(s);

  for (i = 0; i < length; i++) {
    c = s[i];
	
    if ((0x41 <= c && c <= 0x5a) || (0x61 <= c && c <= 0x7a)) {
      b = (c <= 0x5a);

			if (b) {
        c += ' ';
      }
	
      s[i] = 0x7a - (c + 0x9f);

      if (b) {
        s[i] -= 0x20;
      }
    }
  }
  
  puts(s);

  return 0;
}
