# idapython_exercise
Sample IDAPython code for use in the explanation of the advent calendar 2022.


## Exercises 1 (flareon9 chal.4)
This is a CHALLENGE (not a malware) to practice how to extracts the data from IDA and calculations using IDAPython.

The program is Flare-On 9 Challenge #4, "darn_mice".

https://www.mandiant.com/resources/blog/flareon9-challenge-solutions


## Exercises 2 (Emotet old type)
The first step is to practice decoding and commenting decoded strings from a encrypted strings start address as input.  
Finally, it looks for all the addresses of functions that decode strings from the characteristic patterns, parses their arguments, and decodes all encrypted strings.


Ref. 1: https://www.zscaler.jp/blogs/security-research/return-emotet-malware-analysis
Ref. 2: https://jsac.jpcert.or.jp/archive/2021/pdf/JSAC2021_workshop_malware-analysis_jp.pdf 