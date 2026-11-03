// packer.c — Nozita XOR Packer
// cl /O2 /W4 packer.c /link /SUBSYSTEM:CONSOLE /OUT:packer.exe
// usage: packer.exe <input.exe> <output.exe> [key]
// key: 1 byte hex optional (default 0x37)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAGIC 0x4E5A544B   // "NZTK"

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: packer <in.exe> <out.exe> [xor_key_hex]\n");return 1;}
    BYTE key=(BYTE)(argc>=4?(BYTE)strtoul(argv[3],NULL,16):0x37);
    if(!key){fprintf(stderr,"key must not be 0x00\n");return 1;}

    FILE*fi=fopen(argv[1],"rb");
    if(!fi){perror("open input");return 2;}
    fseek(fi,0,SEEK_END); long sz=ftell(fi); rewind(fi);
    BYTE*buf=(BYTE*)malloc(sz);
    if(!buf){fclose(fi);return 3;}
    fread(buf,1,sz,fi); fclose(fi);

    // check it's a PE
    if(sz<2||buf[0]!='M'||buf[1]!='Z'){fprintf(stderr,"not a PE file\n");free(buf);return 4;}

    // XOR encrypt
    for(long i=0;i<sz;i++) buf[i]^=key;

    FILE*fo=fopen(argv[2],"wb");
    if(!fo){free(buf);perror("open output");return 5;}

    // header: magic(4) + original_size(4) + key(1)
    DWORD magic=MAGIC;
    DWORD osz=(DWORD)sz;
    fwrite(&magic,4,1,fo);
    fwrite(&osz,4,1,fo);
    fwrite(&key,1,1,fo);
    fwrite(buf,1,sz,fo);
    fclose(fo); free(buf);

    printf("Packed: %ld bytes  key=0x%02X  -> %s\n",sz,key,argv[2]);
    return 0;
}
