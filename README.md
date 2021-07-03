# post

PoST (Proof of Spcae-Time) is a program for proof of resources. The proof techniqe used by PoST is favoring more usage of memory than traditional proof of work, thus reducing the gap between asic users and standard users while maintaining a relatively simple algorithm. 

# usage

The program can run in two different modes, the generation mode in which the program create a proof for usage of resources, and the verification mode that can check an existing proof.

For genration of proof the flag `-g` must be applied, the hardness parmeter must be specificed using the `-k` flag and the input is given as files.

For exmple genrating a proof with hardness parmeter of 20 bits and input from the file `inp1.txt` and `inp2.txt` will be
```
post -g -k 20 inp1.txt inp2.txt
```
the output is given in the form
```
input1,proof1
input2,proof2
...
```

In the verification mode, one only need to specify the proof file,and apply the flag `-v` for example:
```
post -v proof.txt
```
The output will be in the form
```
filename(0) : failed
filename(1) : passed k = 20
```
