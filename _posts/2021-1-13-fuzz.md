# tl;dr
1) What is fuzzing?
2) why do we need fuzzing?
3)  Architecture of a fuzzer
4) what are the different types of fuzzers?
i) Radamsa
ii) American fuzzy lop(AFL)
iii) Peach fuzzer
iv) Libfuzzer
v) Honggfuzz

## What the fuzz?
Fuzzing is an automated way of testing vulnerabilities in our program by feeding some random input to our program and check whether there is any crash/hang in our program. In some sense fuzzing is like a bruteforce where we run the script until we find any bug,the more complex an application then there is more chance of finiding more bugs. But setting up and writing a perfect code which finds bugs is not easy it takes a lot of time to write a code to an application which is 100% capable of finding bugs. If you are fuzzing an application and found no bugs does it mean that the application is perfectly secure? And every bug that fuzzer founds is an exploitable bug? these are some of the common issues of fuzzing which we go through.

## Why is fuzzing?
We all hear about different bugs such as buffer overflow,rop(return oriented programming),UAF(use after free),integer overflow etc but how do we find these bugs in a program and correct it? with manual testing with our own input and executing the program each time? sounds impossible. So this is the reason of using an automated way of testing which generated inputs and executes the target program and finds any crash in our program.The most important aspect of fuzzing is code coverage where we trace the code coverage reached by each input fed to a fuzz target which is called coverage guided fuzzing or grey box testing  then the fuzzing engine can there by take care of which input should be mutated for maximum code coverage and which inputs should be generated from scratch. There are different types of fuzzing technique and each fuzzer has its own uniqueness. But finding bugs such as memory corruption bugs are easier than finding logical bugs as the program is not obviously not misbehaing and its very tricky to find them out.
##  Architecture of a fuzzer
A fuzzer consist of 3 different parts 
1) A test case generator which generates different test cases to feed to fuzzer to generate the test cases it can either be aware of the structure of the input which is called as smart fuzzer or it can generate without prior knowledge which is known as dumb fuzzer. The test cases which are generated on the previous existing fuzz cases are called mutation based fuzz cases.
2) A worker which executes this inputs and find if there is any unexpected behaviour caused by this input.
3) And a logger which logs intresting test cases and everything that is needed to find a bug. It stores the test case and the bug which is caused by the respective test case so that it would be easier to reproduce the behaviour.

Many fuzzers consists of a server/master which orchestrates the other three parts and manages communication between them.

## Different types of fuzzers

On the first note why do we need different fuzzeing types ? is there any need? well it is obviously yes. There are different types of fuzzers which found different bugs in different applications,Althrough it wont be working on all applications but here is an example of general purpose dumb mutation based fuzzer which is known as Radamsa

### Radamsa
Radamsa is a fuzz case generator which is used to check how well a program can withstand malformed and potentially malicious inputs. It works by reading sample files of valid data and generating interestringly different outputs from them. Radamsa is a negative testing where the software tester have a more or less vague idea what should not happen in a particular application, and they try to find out if this is so. This is opposite to integration fuzzer or positive testing.Radamsa is an extremely black-box fuzzer, because it needs no information about the program nor the format of the data but there are fuzzers which trace the target program and generate/mutate depending on the behaviour of the the particualar input and some needs in a particular format in which the data to pass. The goal of the radamsa is to  find crash no matter what kind of data the program processes, whether it's xml or mp3, and conversely that not finding bugs implies that other similar tools likely won't find them either.

##### Fuzzing with Radamsa
Radamsa is mostly just like a tool in linux platform,radamsa can support more than one output at a time. Radamsa can be fuzzed using a pipe.we get different results every time when we fuzz is for example
$ echo "aaa" | radamsa
 aaaa
when we fuzz the same thing again we get
$ echo "aaa" | radamsa
 ːaaa
By default radamsa will grab a random seed from /dev/urandom if it is not given a specific random state to start from, and you will generally see a different result every time it is started, though for small inputs you might see the same or the original fairly often.

we can generate more than one output by using the -n parameter as follows
$ echo "1 + (2 + (3 + 4))" | radamsa --seed 12 -n 4
 1 + (2 + (2 + (3 + 4?)
 1 + (2 + (3 +?4))
 18446744073709551615 + 4)))
 1 + (2 + (3 + 170141183460469231731687303715884105727))
#### American fuzzy lop(AFL)
AFL is coverage-guided mutation based dumb fuzzer it doesn't need any information about the input structure but due to its intelligent structure design it mostly generates valid inputs where there is more probability of most code coverage.Since most of the fuzzers are  blind, random mutations that makes it very unlikely to reach certain code paths in the tested code, leaving some vulnerabilities firmly outside the reach of this technique. But afl is designed in such a way that there is high probability of maximum code coverage even it is a dumb fuzzer.
##### AFL fuzz approach
We basically load the user input initial test case in a queue and there by we take next input which is present in the queue and we trim the test case in the smallest possible size but its important that it won't loose its measured behaviour which it is supposed to do and there by we mutate the file using a variety of different fuzzing stratergies if we find any new state transition we add the mutated output as a new entry in the queue and take the next input from the queue again.This says how intelligently the AFL was build despite it is a dmb fuzzer.
The overall algorithm can be summed as :-
1) Load user-supplied initial test cases into the queue,
2) Take next input file from the queue,
3) Attempt to trim the test case to the smallest size that doesn't alter the measured behavior of the program,
4) Repeatedly mutate the file using a balanced and well-researched variety of traditional fuzzing strategies,
5) If any of the generated mutations resulted in a new state transition recorded by the instrumentation, add mutated output as a new entry in the queue.
6) Go to 2.
I will be show how AFL works in my next blog post.  
#### Peach fuzzer
 peach fuzzer is a smart fuzzer which is  designed in a highly flexible way where it can be either be a smart or a dumb fuzzer, generating or mutating input depending on the configuration. Its main advantage is its ability to fuzz almost everything where it can produce file based inputs, fuzz network protocols, make web requests and fuzz state aware protocols. Due to its flexibility it needs a significant amount of configuration before the actual fuzzing, therefore it is targeted at experienced testers. Peach requires the creation of PeachPit files that define the structure, type information, and relationships in the data to be fuzzed. It additionally allows for the configuration of a fuzzing run including selecting a data transport (Publisher), logging interface, etc. You can refer [this](https://community.peachfuzzer.com/v2/PeachQuickstart.html) for more information about peech fuzzer and its methadology.
 
#### Libfuzzer
Libfuzzer is a library for coverage-guided in-process fuzzing engine using evolutionary test case generation.The important ascpect in libfuzzer is for every test case the process isn't restarted but the values are changed in memory,this leads to very high speed  and more test cases per second and more code coverage. LibFuzzer is linked with the library under test where it  feeds fuzzed inputs to the library via a specific target function and  then fuzzer tracks which areas of the code are reached, and generates mutations on the corpus of input data in order to maximize the code coverage.

#### Honggfuzz
Honggfuzz is feedback-driven, evolutionary, easy-to-use fuzzer.It's multi-process and multi-threaded:there's no need to run multiple copies of your fuzzer, as honggfuzz can unlock potential of all your available CPU cores with a single running instance.Honggfuzz is very easy to use  feed it a simple corpus directory (can even be empty for the feedback-driven fuzzing), and it will work its way up, expanding it by utilizing feedback-based coverage metrics.

