---
layout: post
title: "Frida walkthrough: tool"
data: 2020-8-25
excerpt: "Frida tool"
tags: [Frida,Introduction]
---
## Frida Walk-through
### Who's this for?
This is for the people who wants to understand function tracing through command line and function hooking such as injecting code and embedding code in a running process and spawning an existing process . So this is a dynamic instrumentation toolkit which lets us to insert snippets of java script into our native apps on any platform such as Linux,windows and mac OS. 
### Why should I use Frida?
Good question!! I will try explaining how easy frida makes function hooking and tracing in a second
  So suppose you want to hook a function and get its output , for those who doesn't know about hooking , so hooking is basically manipulating the function like adding an extra code to the function changing the logic of the program. So how do we do this in minimal cost and time?
  So here frida comes into play it allows us to inject code into program using **java script logic and python API**. Here is an example for frida
  

 

 - You’re building a desktop app which has been deployed at a customer’s site. There’s a problem but the   built-in logging code just isn’t enough. You need to send your customer a custom build with lots of expensive logging code. Then you realize you could just use Frida and build an application- specific tool that will add all the diagnostics you need, and in just a few lines of Python. No need to send the customer a new custom build - you just send the tool which will work on many versions of your app.
### But why Java script logic and python API?
Using Python and JS allows for quick development with a risk-free API. Frida can help you easily catch errors in JS and provide you an exception rather than crashing. 
#### But why should I write in python?
No problem you can write in any programming language  you wish, you can write in C,swift,.Net,Qml
### Modes of operations
#### Table of Contents
- Injected 
- Embedded
- Preloaded
#### Injected 
Most of the time, however, you want to spawn an existing program, attach to a running program, or hijack one as it’s being spawned, and then run your instrumentation logic inside of it. As this is such a common way to use Frida. This functionality is provided by frida-core, which acts as a logistics layer that packages up GumJS into a shared library that it injects into existing software, and provides a two-way communication channel for talking to your scripts, if needed, and later unload them. Beside this core functionality, frida-core also lets you enumerate installed apps, running processes, and connected devices. The connected devices are typically iOS and Android devices where _frida-server_ is running. I will be explaining you how to set up frida server and inject code inside the running apps later.
####  Embedded
It is sometimes not possible to use Frida in Injected mode, for example on jailed iOS and Android systems. For such cases we provide you with _frida-gadget_, a shared library that you’re supposed to embed inside the program that you want to instrument. By simply loading the library it will allow you to interact with it remotely, using existing Frida-based tools like [frida-trace](https://frida.re/docs/frida-trace/). It also supports a fully autonomous approach where it can run scripts off the filesystem without any outside communication.
#### Preloaded
Perhaps you’re familiar with _LD_PRELOAD_, or _DYLD_INSERT_LIBRARIES_? Wouldn’t it be cool if there was _JS_PRELOAD_? This is where _frida-gadget_, the shared library discussed in the previous section, is really useful when configured to run autonomously by loading a script from the filesystem.

### How to attach to a running process and hook it?
 Now I will be explaining how to attach to a running process in frida and report back the function arguments
 first lets create a program and write hello.c  
 ```c
 #include  <stdio.h> 
 #include  <unistd.h>
 void  f  (int  n)
 {
   printf  ("Number: %d\n",  n); 
 }
 int  main  (int  argc,  char  *  argv[])  
 {  
	 int  i  =  0; 
	 printf  ("f() is at %p\n",  f); 
	 while  (1)  
	 {
		   f  (i++);  sleep  (1);  
	  }
}
```
Now compile the program with  **gcc -Wall hello.c -o hello**
Now open your terminal and run the process hello, you will get the address of f() function and value of i in an infinite loop
![image](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2015-25-39.png)
Now looking for all connected processes in our laptop just type **frida-ps** by executing this command we will get the following output
![img](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2015-27-27.png)
That means our hello process is ready to attach(**Note: We can only attach running processes and spawn existing process**) . Now we will write a frida script which hook calls to functions inside a target process and report back a function argument to you.
We first import all the packages 
```py
from __future__ import print_function
import frida
import sys
```
Now we attach to frida to the running process **hello**  . Create an hello.py and start writing the above code
```py
session = frida.attach("hello")
``
def  on_message(message,  data): 
	  print(message) 
	  script.on('message',  on_message)  
	  script.load() 
	  sys.stdin.read()
```
Our final script looks like this 
```py
from  __future__  import  print_function
import  frida
import  sys
session  =  frida.attach("hello")
script  =  session.create_script("""Interceptor.attach(ptr("%s"), {
  onEnter: function(args) {  
  send(args[0].toInt32());
    }
  });  
  """ %  int(sys.argv[1],  16))  
  def  on_message(message,  data):
    print(message)  
    script.on('message',  on_message)  
  script.load()  
  sys.stdin.read()
```
Run this script with the address you picked out from above (`0x55ddd01d968a`) on our example
This should give you a new message every second on the form:
![img](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2018-16-14.png)
We can see every second there is a new message on the form, now lets understand how we hooked this function 
```py
script = session.create_script("""
Interceptor.attach(new NativePointer("%s"), {
    onEnter: function(args) {
        send(args[0].toInt32());
    }
});
""" % int(sys.argv[1], 16))
```
This is the most important part of our program where we pass our address ```0x55ddd01d968a``` as a format string i.e argv[1] value as we know that argv[0] is our program name itself. Then our function is hooked and there by we pass our function arguments i.e 
```js
onEnter : function(args) {
		send(args[0].toInt32());
		}
```		
and send the args[0] by converting it to int.
so in this way our message is sent sent to on_message and the output is printed.
### Modifying function arguments
Now let us make a slight modification to the program and make our script something like 
```js
Interceptor.attach(ptr("%s"),
 {
	   onEnter: function(args) {
		     args[0] = ptr("1337"); 
		} 
 });
```
As at this stage our code looks like this
```py
  import  frida
  import  sys  
  session  =  frida.attach("hello")  
  script  =  session.create_script("""Interceptor.attach(ptr("%s"), {
        		  onEnter: function(args) 
		         {  
			        args[0] = ptr("1337"); 
			     } 
		 });  
		 """ %  int(sys.argv[1],  16))  
		 script.load() 
		 sys.stdin.read()
```		 
Run this script with the address you picked out from above (```0x5652cf1b468a``` on our example):
and running this in the same way we did previously we see that it always reports **1337** until you hit 
ctrl-D 
![hook](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2020-15-06.png)

So this means we successful hooked this program and changes the execution of the program by modifying the arguments of the program .
### Calling functions
We can use Frida to call functions inside a target process. That means we can call a function using frida , lets look how can we do that
```py
import frida
import sys
session=frida.attach("hello")
script=session.create_script{"""
var f=new NativeFunction(ptr("%s"), 'void',['int']);
f(1919);
f(1919);
f(1919);
""" % int(sys.argv[1],16))
script.load()
```
The **new NativeFunction(ptr("%s"), 'void', ['int'])** here ptr("%s") is new NativePointer("%s") which was defined before ptr is just written for simplicity and void is the return type of the program and int is the argument we pass to the program for example f(1919) where we passed an integer.
So when we run this we get
![img](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2021-07-45.png)
### Injecting strings and calling a function
So far we injected integers into the program. So now let us inject string.
```c
 #include  <stdio.h>
 #include  <unistd.h>  
 int  f  (const  char  *  s) 
 {
        printf  ("String: %s\n",  s);
        return  0; 
 } 
 int  main  (int  argc,  char  *  argv[]) 
{  
	const  char  *  s  =  "Testing!";
	printf  ("f() is at %p\n",  f);  
	printf  ("s is at %p\n",  s);
	while  (1)  
	{
		  f  (s); 
		  sleep  (1);
   }
}   
```
Now we will inject a string into it and see the magic in between the program when we execute the string
In order to manipulate the process memory with ease we can use **Memory.alloc()** and **Memory.protect()**.
So in this way we will manipulate the process memory with a string we do that with **Memory.allocUtf8String("Any string")**
```py
from __future__ import print_function
import frida
import sys
session=frida.attach("hi")
script=session.create_script("""
var st = Memory.allocUtf8String("Frida is great!!");
var f = new NativeFunction(ptr("%s"),'int',['pointer']);
f(st);
""" % int(sys.argv[1],16))
def on_message(message,data):
	print(message)
script.on('message',on_message)
script.load()
```
And the output of this is 
![outpu1](https://raw.githubusercontent.com/P-Vishnu-Madhav/Writeups_files/master/Screenshot%20from%202020-08-25%2021-45-51.png)
If we see into the output whenever I execute my frida script it prints "Frida is great!!" and each time I execute in a similar way the string is executed in the similar fashion.

### Setting up Frida Server to hack vulnerable android apps
1) Download Genymotion in your laptop/computer
2) Run your custom phone in genymotion in terminal custom phone custom phone API 23 is highly recommended to download.
3) Download [frida-server-12.11.9-android-x86_64.xz](https://github.com/frida/frida/releases)
4) Rename frida-server-12.11.9-android-x86_64.xz as frida-server  
5) ./adb push frida-server /data/local/tmp/
6) ./adb shell "chmod 755 /data/local/tmp/frida-server"
7) start the server using ./adb shell /data/local/tmp/frida-server &
8) start server using frida-ps -U

You will get all the connected devices to your laptop. In my case it is 
```
 PID  Name
----  ------------------------------
  86  adbd
 865  android.process.acore
 954  android.process.media
 229  batteryd
1247  com.android.calendar
1030  com.android.deskclock
1110  com.android.dialer
1282  com.android.email
1303  com.android.exchange
 750  com.android.inputmethod.latin
 826  com.android.launcher
1189  com.android.mms
 919  com.android.music
1394  com.android.musicfx
1215  com.android.onetimeinitializer
 783  com.android.phone
 837  com.android.printspooler
1145  com.android.providers.calendar
 766  com.android.settings
 894  com.android.smspush
 676  com.android.systemui
1230  com.android.voicedialer
 811  com.genymotion.genyd
1317  com.genymotion.superuser
 798  com.genymotion.systempatcher
 235  debuggerd
1096  dhcpcd
 233  diskiod
 238  drmserver
1455  frida-server
  78  genybaseband
 250  healthd
   1  init
 240  installd
 241  keystore
 227  local_camera
 228  local_camera
 226  local_opengl
1379  logcat
  77  logwrapper
 239  mediaserver
 234  netd
 231  network_profile
  83  redis
 236  rild
  84  sdcard
 222  servicemanager
 232  settingsd
  85  sh
1376  sh
 242  su
 582  surfaceflinger
 615  system_server
  65  ueventd
 225  vinput
 223  vold
 852  wpa_supplicant
 237  zygote
```
### Having problems in installing diva in your virtual device? Follow the following commands
9) kill the root process i.e the output of ./frida-server & with **kill -9 ./frida-server & output**
output is the number when you do **./frida-server &**
10) And then check ./frida-server &  
11) ./adb forward tcp:1249 tcp: 1343
You can give any port number  but the default port it listens is 27042.
12) install  jakhar.aseem.diva by ./adb push 
13) run frida -U -f jakhar.aseem.diva

You are all set to start diva(damn insecure vulnerable application)

You can check [here]([https://frida.re/docs/javascript-api/](https://frida.re/docs/javascript-api/)) for java script tutorial. 

I will posting all the solutions for diva in my next post.
Thank you for reading this post hope you are now familiar with frida usage and advantage.




