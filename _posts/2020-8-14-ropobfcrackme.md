---
layout: post
title: "rop-obf: Writeup"
data: 2020-8-14
excerpt: "Crackmes.one writeup"
tags: [Writeup,Z3]
---
This is a level-3(medium level) crackme which was taken from [crackmes.one](https://crackmes.one/crackme/5cfb961a33c5d41c6d56e069) the aim of the crackme is to print "1" at the end. We can give some random inputs and understand that the it takes 6 inputs and prints "0" if it is wrong else prints "1" if it is correct.
So we will set a break point at the point where our input is being taken i.e at scanf . So at every input there is some check that is happening it will be xored with our input and and later compared with the actual result . So basically if all our inputs are correct it just prints "1" which is obvious.
So I gave some random input and saw that my first input is xored with ```0x83``` and compares with ```0x87``` . So basically these type of constraint based challenges can be solved easily with the help of **z3**.
![xor1](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-14%2010-52-55.png)
The random input I gave was 6 and the input is xored with 0x83
![result](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-14%2010-55-32.png)
And it is compared with 0x87
And similarly 2nd input is xored with ```0x36``` and compares with the result ```0x3e``` . The third input is xored with ```0x9d``` and compares with ```0x92```. The fourth input is xored with ```0xcd``` and compares with ```0xdd```. The fifth input is xored with ```0xec``` and compares with ```0xfb```. The the final input is xored with ```0xf6``` and compares with  ```0xdc```

So we know the list of xored values  and the result of the xor, so basically we can apply z3 constraint solver and extract the correct values through it.

Here is my small python script which can extract the values

```py
from z3 import *
s=Solver()
array=[BitVec("array%i"%i,32) for i in range(6)]

s.add(array[0]^0x83==0x87)
s.add(array[1]^0x36==0x3e)
s.add(array[2]^0x9d==0x92)
s.add(array[3]^0xcd==0xdd)
s.add(array[4]^0xec==0xfb)
s.add(array[5]^0xf6==0xdc)

if s.check()==sat:
    flag=s.model()
    for i in range(6):
        ans=((flag[array[i]]))  
        print(ans)
```
And we get our input as 4,8,15,16,23,42 which prints "1" 
![answer](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-14%2011-06-11.png)
Thank you for reading my writeup hope you all enjoyed :)


