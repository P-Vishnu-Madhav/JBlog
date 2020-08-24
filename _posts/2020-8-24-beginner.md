
---
layout: post
title: "Beginner: Writeup"
data: 2020-8-24
excerpt: "Angr,Symbolic Execution"
tags: [Writeup,Symbolic Execution]
---
Recently I played GoogleCTF and had a lot of fun solving begineer and Android challenges. This challenge was the warmup for Revering category . Althroughthe challenge can be solved in manyways but symbolic execution is the best way which saves a lot of time than other techniques.
 
You can find out the challenge file [here](https://github.com/P-Vishnu-Madhav/Writeups_files/blob/master/a.out). So running the binary we see that it 
asks for flag and prints **SUCCESS** if the flag is correct else it prints **FAILURE**.

So looking into the decompilation of the binary through ghidra 
![img](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-24%2022-22-05.png)
We can see that there are 2 string comparisions there and its preety obvious that if the comparision is same it prints out the flag.So looking into
the operations done before string compare through GDB we can find out that there is a shuffle taking place in the input we give and then our input is manipulated through Add32 and xored.

[img](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-24%2022-37-33.png)

The operations looks little tricky and takes time to understand properly and write a script for the following. What to do now :/ ??!

Dont worry we dont need to go through each and every operation and understand it :P , instead of that we can simply write a small script using angr with find and avoid conditions and print the flag :)

![image](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-24%2022-47-52.png) 

So here we can see the address that we need to explore(**SUCCESS**) and avoid the address which leads to **FAILURE**. We can see that the length must be 15 characters.we can simply add constraints for this 15 charaters to print it in a printable range and explore the SUCCESSS address and avoid the FAILUREaddress.

```py
import angr
import claripy
import sys
proj=angr.Project('./a.out',load_options={'auto_load_libs':False},main_opts={'base_addr':0x100000})
flag=[claripy.BVS('flag%i'%i,8) for i in range(15)]
flag_concat=claripy.Concat(*flag + [claripy.BVV("\n")])
state=proj.factory.entry_state(stdin=flag_concat)
for i in flag:
    state.solver.add(i>=32)
    state.solver.add(i<=127)
simgr=proj.factory.simgr(state)
simgr.explore(find=0x101124,avoid=0x10110d)
if simgr.found:
    simulation=simgr.found[0]
    print(simulation.posix.dumps(sys.stdin.fileno()))
else:
    print("FAILURE")    
```
So the above script looks quite simple by running this script we get the flag 

![flag](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2000-00-29.png)

Flag: CTF{S1MDf0rM3!}

Hope you enjoyed reading my writeup and got some idea about symolic execution and solver engine  in angr.Thank you for reading :)
