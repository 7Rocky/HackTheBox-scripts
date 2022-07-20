#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
  int i;
  int length;
	char c;
  char* s;

  s = argv[1];
  length = strlen(s);

  for (i = 0; i < length; i++) {
    if (0x20 < s[i] && s[i] != 0x7f) {
      c = (char) (s[i] + 0x2f);
	
      if (s[i] + 0x2f < 0x7f) {
				s[i] = c;
			} else {
        s[i] = c - 0x5e;
      }
    }
  }
  
  puts(s);

  return 0;
}
