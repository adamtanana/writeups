# Protostar Stack levels

## Stack 0
For this level we have to exploit the following C code.

```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)  
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
    printf("you have changed the 'modified' variable\n");
  } else {
    printf("Try again?\n");
  }
}
```

As we can see here. The main function is calling `gets()`.
Running `man gets` we see it is a C library function which reads a line from standard input and stores the string inside the supplied buffer.
The man page also warns that gets does not check for the size of the string! 

The program starts by initialising the stack. The stack looks like this. 
```C
Data...
buffer[64]
modified
More data...
```
Since this a 32 bit system, modified will be 4 bytes (32 bits = 4 bytes). So we can type 1 to 4 characters to overwrite it.
The modified variable is right above the buffer, we need to write 64 characters to fill the buffer, then 1 character to change modified.

We can do this with a nice little python script: Piping the followning output into the program will overwrite the modified variable
```python
print 'A'*64 + 'BBBB'
```


##Stack 1

Here is the supplied C Code
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)  
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
    errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
    printf("you have correctly got the variable to the right value\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }
}
```

Stack1 is very similar to Stack0, however now we have to write a specific value into the buffer. Specifically 0x61626364
This is a hex number, 0x61 = 91. 

Let's take a step back and talk about *endianness*. Computers are really lazy.
Modern computers store data in many ways. The most common is in a format called **little endian**.
Little endian stores the least significant byte first. This means that if you wanted to store the binary number *01101001*, it would be stored as *01101001*. But if you wanted to store a 4 byte word, (0xFF = 11111111, 0x00 = 00000000), In memory storing **0x123456** would look like **0x563412**. Little endianness changes the location of entire *bytes*, not the *bits*.
This challenge is extremely similar to Stack 0. But in order to get the number *0x61626364* to appear correctly, we would have to enter it in a little endian manner. This means enterring **0x64636261**.
The program is expecting characters not numbers, so we have to convert each byte, into a character. For example 0x61 = *[*.
But this is annoying to do, python has a nice short hand to doing it, if you just `print '\x61'` it will print [. 

So similar to Stack 0, we can use the following python script to print our attack
```python
print "A"*64 + "\x64\x63\x62\x61"
```
To pipe this input into our program we can do `python -c 'print "A"*64 + "\x64\x63\x62\x61"' | ./stack1`

##Stack 2

Supplied C Code is
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)  
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
    errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
    printf("you have correctly modified the variable\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }

}
```
