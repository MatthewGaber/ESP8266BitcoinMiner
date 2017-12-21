#include <SPI.h>
#include "Crypto.h"
#include <stdint.h>

SHA256 hasher;
SHA256 hashagain;

char header_hex[] = "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695";

uint8_t hashbytes[80];

uint8_t* hex_decode(const char *in, size_t len, uint8_t *out)
{
        unsigned int i, t, hn, ln;

        for (t = 0,i = 0; i < len; i+=2,++t) {

                hn = in[i] > '9' ? in[i] - 'a' + 10 : in[i] - '0';
                ln = in[i+1] > '9' ? in[i+1] - 'a' + 10 : in[i+1] - '0';

                out[t] = (hn << 4 ) | ln;
        }

        return out;
}

void hash(){
 
  hex_decode(header_hex,strlen(header_hex),hashbytes); 
  unsigned long start = micros();
  hasher.doUpdate(hashbytes, sizeof(hashbytes));
  byte hash[SHA256_SIZE];
  hasher.doFinal(hash);

  hashagain.doUpdate(hash, sizeof(hash));
  byte hash2[SHA256_SIZE];
  hashagain.doFinal(hash2);
 
  unsigned long ended = micros();
  unsigned long delta = ended - start;
  Serial.println(delta);
  Serial.print("Big Endian: ");
  for (byte i=32; i > 0; i--)
   {
     if (hash2[i-1]<0x10) { Serial.print('0'); }
      Serial.print(hash2[i-1], HEX);
   }
   
   Serial.println();
   Serial.print("Little Endian: ");
   for (byte i=0; i < SHA256_SIZE ; i++)
   {
     if (hash2[i]<0x10) { Serial.print('0'); }
      Serial.print(hash2[i], HEX);
   }
    
}

void setup() {
  
  Serial.begin(115200); 
  hash(); 
  
}

void loop() {
  
}
