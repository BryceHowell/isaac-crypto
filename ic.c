/*
by JAMES BRYCE HOWELL
added directly on top of Bob Jenkins' random number generator ISAAC
This is a symmetric key cipher scheme and utility for file encryption.
A feedforward element is used so that ciphering is not simply XORing 
plaintext and CPRNG output.

Creation for use by others in April of 2020
*/



/*
------------------------------------------------------------------------------
rand.c: By Bob Jenkins.  My random number generator, ISAAC.  Public Domain.
MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: added main (ifdef'ed out), also rearranged randinit()
  010626: Note that this is public domain
------------------------------------------------------------------------------
*/
#ifndef STANDARD
#include "standard.h"
#endif
#ifndef RAND
#include "ic.h"
#endif
#include <unistd.h>

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ind(mm,x)  (*(ub4 *)((ub1 *)(mm) + ((x) & ((RANDSIZ-1)<<2))))
#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
  x = *m;  \
  a = (a^(mix)) + *(m2++); \
  *(m++) = y = ind(mm,x) + a + b; \
  *(r++) = b = ind(mm,y>>RANDSIZL) + x; \
}

void     isaac(ctx)
randctx *ctx;
{
   register ub4 a,b,x,y,*m,*mm,*m2,*r,*mend;
   mm=ctx->randmem; r=ctx->randrsl;
   a = ctx->randa; b = ctx->randb + (++ctx->randc);
   for (m = mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
   {
      rngstep( a<<13, a, b, mm, m, m2, r, x);
      rngstep( a>>6 , a, b, mm, m, m2, r, x);
      rngstep( a<<2 , a, b, mm, m, m2, r, x);
      rngstep( a>>16, a, b, mm, m, m2, r, x);
   }
   for (m2 = mm; m2<mend; )
   {
      rngstep( a<<13, a, b, mm, m, m2, r, x);
      rngstep( a>>6 , a, b, mm, m, m2, r, x);
      rngstep( a<<2 , a, b, mm, m, m2, r, x);
      rngstep( a>>16, a, b, mm, m, m2, r, x);
   }
   ctx->randb = b; ctx->randa = a;
}


#define mix(a,b,c,d,e,f,g,h) \
{ \
   a^=b<<11; d+=a; b+=c; \
   b^=c>>2;  e+=b; c+=d; \
   c^=d<<8;  f+=c; d+=e; \
   d^=e>>16; g+=d; e+=f; \
   e^=f<<10; h+=e; f+=g; \
   f^=g>>4;  a+=f; g+=h; \
   g^=h<<8;  b+=g; h+=a; \
   h^=a>>9;  c+=h; a+=b; \
}

/* if (flag==TRUE), then use the contents of randrsl[] to initialize mm[]. */
void randinit(ctx, flag)
randctx *ctx;
word     flag;
{
   word i;
   ub4 a,b,c,d,e,f,g,h;
   ub4 *m,*r;
   ctx->randa = ctx->randb = ctx->randc = 0;
   m=ctx->randmem;
   r=ctx->randrsl;
   a=b=c=d=e=f=g=h=0x9e3779b9;  /* the golden ratio */

   for (i=0; i<4; ++i)          /* scramble it */
   {
     mix(a,b,c,d,e,f,g,h);
   }

   if (flag) 
   {
     /* initialize using the contents of r[] as the seed */
     for (i=0; i<RANDSIZ; i+=8)
     {
       a+=r[i  ]; b+=r[i+1]; c+=r[i+2]; d+=r[i+3];
       e+=r[i+4]; f+=r[i+5]; g+=r[i+6]; h+=r[i+7];
       mix(a,b,c,d,e,f,g,h);
       m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
       m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
     }
     /* do a second pass to make all of the seed affect all of m */
     for (i=0; i<RANDSIZ; i+=8)
     {
       a+=m[i  ]; b+=m[i+1]; c+=m[i+2]; d+=m[i+3];
       e+=m[i+4]; f+=m[i+5]; g+=m[i+6]; h+=m[i+7];
       mix(a,b,c,d,e,f,g,h);
       m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
       m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
     }
   }
   else
   {
     /* fill in m[] with messy stuff */
     for (i=0; i<RANDSIZ; i+=8)
     {
       mix(a,b,c,d,e,f,g,h);
       m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
       m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
     }
   }

   isaac(ctx);            /* fill in the first set of results */
   ctx->randcnt=RANDSIZ;  /* prepare to use the first set of results */
}

unsigned char reverse_table[256];

void make_reverse_table(void) {
	for (int i=0; i<256; i++) {
		unsigned char x=i;
		unsigned char c=0;
		for (int j=0; j<8; j++) {
		     unsigned char grab=x & (1 << j);
		     if (grab) c|=(1 << (7-j));
	             }
		reverse_table[i]=c;
	}
}

uint64_t reversebits(uint64_t W) {
	unsigned char * b=(unsigned char *)(&W);
	int i,j;
	unsigned char t;
	for (i=0,j=7; i<4; i++,j--) {
		t=b[j]=reverse_table[b[j]];
		b[j]=reverse_table[b[i]];	
		b[i]=t;
	}
	return W;
}

uint64_t weirdfrompwd(unsigned char * P, int length) {
	uint64_t W=15583522643116493073ULL;
	for (int i=0, j=length-1; i<length; i++,j--) {
		W+=P[i];
		W^=((uint64_t)(P[j])<<32);
		W*=13168257484146441411ULL;
		W=reversebits(W);
	}
	W*=13168257484146441411ULL;
	W=reversebits(W);
	return W;
}

void map_passphrase_to_state(randctx * ctx, unsigned char * pass, int length) {
	int i,l=0;
	for (i=0; i<256; i++) {
		for (l=0; l<length; ++l) {
			ctx->randrsl[i]+=(ub4)pass[l];
			ctx->randrsl[i]=ctx->randrsl[i]<<8 | ctx->randrsl[i]>>24;
			i++;
			i%=256;
		}
	}

}


//#ifdef NEVER
int main(int argc, char **argv)
{
  if (argc!=5 && argc!=4) {
	  fprintf(stderr,"USAGE: ic <commandstring> passphrase input-file [output-file]\n");
	  fprintf(stderr,"       <commandstring> is a list of single characters for commands and modes\n");
	  fprintf(stderr,"          e- encrypt\n");
	  fprintf(stderr,"          d- decrypt\n");
	  fprintf(stderr,"          r- reveal intial state data\n");
	  fprintf(stderr,"          t- troubleshoot the ciphering process\n");
	  goto exiting;
  }
  char flagchar=argv[1][0];
  int modeflag=0;
  int show_state=0;
  int debug_mode=0;
  int debug_counter=0;
  for (int i=0; i<strlen(argv[1]); i++) {
  	char flagchar=argv[1][i];
	switch(argv[1][i]) {
		case 'e':
		case 'E':
	  		fprintf(stderr,"Encryption mode.\n");
	  		modeflag=0;
			break;
		case 'd':
		case 'D':
	  		fprintf(stderr,"Decryption mode.\n");
	  		modeflag=1;
			break;
		case 'r':
		case 'R':
	  		fprintf(stderr,"Reveal state from passphrase.\n");
	  		show_state=1;
			break;
		case 't':
		case 'T':
			fprintf(stderr,"Troubleshooting mode.\n");
			debug_mode=1;
			break;
		default:
	  		fprintf(stderr,"%c\n",flagchar);
	  		fprintf(stderr,"Invalid command.\n");
	  		goto exiting;
  	}
  }

  int fd_in,fd_out;
  if ((fd_in=open(argv[3],O_RDONLY))==-1) { fprintf(stderr,"Cannot open input file.\n"); goto exiting; }
  if (argc==4) fd_out=STDOUT_FILENO; else
  	if ((fd_out=open(argv[4],O_WRONLY | O_CREAT | O_TRUNC))==-1) { fprintf(stderr,"Cannot open output file.\n"); goto exiting; }
  ub4 i,j;
  randctx ctx;
  ctx.randa=ctx.randb=ctx.randc=(ub4)0;
  // NEED TO SET INITIAL STATE BETTER
  for (i=0; i<256; ++i) ctx.randrsl[i]=(ub4)0;
  map_passphrase_to_state(&ctx,argv[2],strlen(argv[2]));
  //randinit(&ctx, TRUE);
  
  make_reverse_table();
  uint64_t weird=weirdfrompwd(argv[2],strlen(argv[2])); 

  if (show_state) {
	  fprintf(stderr,"Weird feedforward variable: %08lX \n",weird);
	  fprintf(stderr,"RANDA, RANDB, RANDC: %08lX %08lX %08lX\n",ctx.randa,ctx.randb,ctx.randc);
	  fprintf(stderr,"RANDCNT: %ld\n",ctx.randcnt);
	  fprintf(stderr,"RANDRSL ARRAY:\n");
	  for (int i=0; i<8; i++) { 
		  for (int j=0; j<8; j++) fprintf(stderr,"%08lX ",ctx.randrsl[8*i+j]);
		  fprintf(stderr,"\n");
		  }
	  fprintf(stderr,"RANDMEM ARRAY:\n");
	  for (int i=0; i<8; i++) { 
		  for (int j=0; j<8; j++) fprintf(stderr,"%08lX ",ctx.randmem[8*i+j]);
		  fprintf(stderr,"\n");
		  }
  }
  randinit(&ctx, TRUE);

  unsigned char * W=(unsigned char *)&weird;
  unsigned char buffer[65536]; 
  unsigned char weirdbyte;
  unsigned char random,cipher,plain;
  int received=0;
  int locus=0;
  int rng_locus=1024;
  unsigned char * R=(unsigned char *)(ctx.randrsl);
  for (;;)
  {
    if (rng_locus>=1024) {
    	isaac(&ctx);
	rng_locus=0;
    	} 
    if (locus>=received) {
	  received=read(fd_in,buffer,65536);
	  locus=0;
	  if (received<=0) {
		  close(fd_in);
		  close(fd_out);
		  fprintf(stderr,"Ciphering complete.\n");
	  	  goto exiting;
		  }
	  }
    	  plain=buffer[locus];
	  random=R[rng_locus];
	  locus++; rng_locus++;
	  weirdbyte=((W[0]+W[1])^~(W[2]+W[3]))+~((W[4]+W[5])^~(W[6]+W[7]));
	  cipher=plain^(random+weirdbyte); 
	  if (debug_mode) {
		  debug_counter++;
		  fprintf(stderr,"cipher: %02X plain: %02X random: %02X weirdbyte: %02X weird: %016X\n",
			(unsigned int)cipher,(unsigned int)plain,(unsigned int)random,(unsigned int)weirdbyte,
			(unsigned int)weird); 
		  if (debug_counter==16) goto exiting;
	  }
	  write(fd_out,(void *)(&cipher),1);
	  //if (modeflag==0) weird+=(uint64_t)plain; else weird+=(uint64_t)cipher;
	  weird=(weird<<17) | (weird>>47);
	  weird^=(uint64_t)random;
	  weird*=2665364157445947747;
	  weird=reversebits(weird);
  }
exiting:
  close(fd_in);
  close(fd_out);
}
//#endif
