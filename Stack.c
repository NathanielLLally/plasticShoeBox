/*
 * This file was generated automatically by xsubpp version 1.9508 from the
 * contents of Stack.xs. Do not edit this file, edit Stack.xs instead.
 *
 *	ANY CHANGES MADE HERE WILL BE LOST!
 *
 */

#line 1 "Stack.xs"
/*
 *  packages: Stack Registers DisAsm Cpu
 *
 *  Nate Lally  nate[at]airitechsecurity[dot]com
 *
 *  Changelog:
 *
 *
 **********************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "insns.h"
#include "nasm.h"
#include "nasmlib.h"
#include "sync.h"

#include "pe.h"

#ifdef __cplusplus
}
#endif

// General register set
// eax: accumulator
// ebx: base
// ecx: count
// edx: data
// ebp: base pointer
// esi: source index
// edi: destination index
// esp: stack pointer
// eip: instruction pointer

// access to segment registers
#define SR_ES (MY_CXT.sreg[0].word.rx)
#define SR_CS (MY_CXT.sreg[1].word.rx)
#define SR_SS (MY_CXT.sreg[2].word.rx)
#define SR_DS (MY_CXT.sreg[3].word.rx)
#define SR_FS (MY_CXT.sreg[4].word.rx)
#define SR_GS (MY_CXT.sreg[5].word.rx)

// access to 8 bit general registers
#define R_AL (MY_CXT.reg[0].word.byte.rl)
#define R_CL (MY_CXT.reg[1].word.byte.rl)
#define R_DL (MY_CXT.reg[2].word.byte.rl)
#define R_BL (MY_CXT.reg[3].word.byte.rl)
#define R_AH (MY_CXT.reg[0].word.byte.rh)
#define R_CH (MY_CXT.reg[1].word.byte.rh)
#define R_DH (MY_CXT.reg[2].word.byte.rh)
#define R_BH (MY_CXT.reg[3].word.byte.rh)

// access to 16 bit general registers
#define R_AX (MY_CXT.reg[0].word.rx)
#define R_CX (MY_CXT.reg[1].word.rx)
#define R_DX (MY_CXT.reg[2].word.rx)
#define R_BX (MY_CXT.reg[3].word.rx)
#define R_SP (MY_CXT.reg[4].word.rx)
#define R_BP (MY_CXT.reg[5].word.rx)
#define R_SI (MY_CXT.reg[6].word.rx)
#define R_DI (MY_CXT.reg[7].word.rx)
#define R_IP (MY_CXT.reg[8].word.rx)

// accesss to 32 bit general registers
#define R_EAX (MY_CXT.reg[0].dword.erx)
#define R_ECX (MY_CXT.reg[1].dword.erx)
#define R_EDX (MY_CXT.reg[2].dword.erx)
#define R_EBX (MY_CXT.reg[3].dword.erx)
#define R_ESP (MY_CXT.reg[4].dword.erx)
#define R_EBP (MY_CXT.reg[5].dword.erx)
#define R_ESI (MY_CXT.reg[6].dword.erx)
#define R_EDI (MY_CXT.reg[7].dword.erx)
#define R_EIP (MY_CXT.reg[8].dword.erx)


/* 31|30|29|28|27|26|25|24|23|22|21|20|19|18|17|16
 * ==|==|=====|==|==|==|==|==|==|==|==|==|==|==|==
 *  0| 0| 0| 0| 0| 0| 0| 0| 0| 0|ID|VP|VF|AC|VM|RF
 *
 * 15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0
 * ==|==|=====|==|==|==|==|==|==|==|==|==|==|==|==
 *  0|NT| IOPL|OF|DF|IF|TF|SF|ZF| 0|AF| 0|PF| 1|CF
 */

#define EF_CF     0x00000001
#define EF_PF     0x00000004
#define EF_AF     0x00000010
#define EF_ZF     0x00000040
#define EF_SF     0x00000080
#define EF_OF     0x00000800

/* registers
 * 4 bytes with dword, word, and byte accessors */
typedef struct {
  union {
    struct {
      U32 erx;
      } dword;
    struct {
      union {
        U16 rx;
        struct {
          U8 rl;
          U8 rh;
          } byte;
        };
      U16 word_filler;
      } word;
    };
} reg_t;

typedef reg_t sreg_t;

/* file structs */
static enum {
  MZ_HDR,
  PE_HDR
} headerType;

typedef struct {
  union {
    struct {
      U32 offset;
      DWORD Signature;
      IMAGE_FILE_HEADER h;
      IMAGE_OPTIONAL_HEADER opt;
      IMAGE_SECTION_HEADER section[16];
      IMAGE_IMPORT_DESCRIPTOR *import;
    } pe;
    U8 type;
  } hdr;
  void *data;
  U32 ep;
  U32 base;
} executableImage;

static U32
rvaToOffset(U32 rva)
{
  return rva;
}


static HV *
disAsm(executableImage *ei, U32 offset)
{
  U8 done = FALSE, i;
  unsigned char *pos;
  char outbuf[256];
  unsigned long nextsync, synclen, lendis = 0;
  HV *ret;
  AV *bytes;

  /* autosync causes ndisasm to place a sync point on the 
   *   byte any forward branch refers to 
   * flags refers to intel, amd, cyrix, idt, winchip
   */
  int bits = 32, autosync = TRUE, lenread = 0, flags = 0;

  nextsync = next_sync (offset, &synclen);

  pos = ei->data - ei->base + offset;

  lendis = disasm (pos, outbuf, bits, offset, autosync, flags);

  ret = (HV *)sv_2mortal((SV *)newHV());

  hv_store(ret, "len", 3, newSViv(lendis), 0);
  if (lendis != 0) {
    bytes = (AV *)sv_2mortal((SV *)newAV());
    for (i=0; i<lendis; i++) {
      av_push(bytes, newSViv(*(U8 *)(pos + i)));
    }
    hv_store(ret, "bytes", 5, newRV((SV *)bytes), 0);
    hv_store(ret, "asm", 3, newSVpv(outbuf, strlen(outbuf)), 0);
  }
  return ret;
}

/*
 *  load:  detects type and loads file
 *
 *  returns: -1 file not found
 *            0 type not known
 *            1 load successful
 *
 *  TODO: support executable formats other than PE
 ****************************************************/
static int
load(char *file, executableImage *ei)
{
  FILE *fh;
  char *inp;
  int ret = 1, i;

  const static struct {
    unsigned char MZ[2];
    unsigned char PE[4];
  } fsig = {
    {0x4d, 0x5a},
    {0x50, 0x45, 0, 0}
  };

  fh = fopen(file, "rb");
  if (fh == NULL) return -1;

  inp = (char *)alloca(4);

  //detect file type
  //MZ
  fread(inp, 2, 1, fh);
  if ((*(U16 *)inp) != *(U16 *)fsig.MZ) goto loaderr;
  ei->hdr.type = MZ_HDR;

  //PE offset
  fseek(fh, 0x3c, SEEK_SET);
  fread(inp, 4, 1, fh);
  ei->hdr.pe.offset = *(U32 *)inp;

  //read pe headers
  fseek(fh, ei->hdr.pe.offset, SEEK_SET);
  fread((void *)&ei->hdr.pe.Signature, sizeof(ei->hdr.pe.Signature), 1, fh);
  fread((void *)&ei->hdr.pe.h, sizeof(ei->hdr.pe.h), 1, fh);
  fread((void *)&ei->hdr.pe.opt, sizeof(ei->hdr.pe.opt), 1, fh);

  //check signature
  if (ei->hdr.pe.Signature != *(U32 *)fsig.PE) goto loaderr;

  //load import table
  //  ei->hdr.pe.opt.

  //load section headers
  fread((void *)&ei->hdr.pe.section, sizeof(ei->hdr.pe.section[0]), 
	ei->hdr.pe.h.NumberOfSections, fh);

  //prepare context struct
  ei->hdr.type = PE_HDR;
  ei->ep = ei->hdr.pe.opt.AddressOfEntryPoint;
  ei->base = ei->hdr.pe.opt.ImageBase;
  ei->data = safemalloc(ei->hdr.pe.opt.SizeOfImage);
  memset(ei->data, 0, ei->hdr.pe.opt.SizeOfImage);

  //load sections
  for (i=0; i < ei->hdr.pe.h.NumberOfSections; i++ ) {
    if (fseek(fh, ei->hdr.pe.section[i].PointerToRawData, SEEK_SET) == EOF) {
      printf("error loading section %s (fseek)\n", ei->hdr.pe.section[i].Name);
      goto loaderr;
    }
    fread(ei->data + ei->hdr.pe.section[i].VirtualAddress, 
	  ei->hdr.pe.section[i].SizeOfRawData, 1, fh);
  }

  goto loadret;
 loaderr:
  ret = 0;
 loadret:
  fclose(fh);
  return ret;
}

static void
printfstat(executableImage *ei)
{  
  int i;
  if (ei->hdr.pe.h.Characteristics &
      IMAGE_FILE_DEBUG_STRIPPED > 0)
    printf("stripped ");
  
  if (ei->hdr.pe.h.Characteristics &
      IMAGE_FILE_RELOCS_STRIPPED > 0)
    printf("non-relocateable ");

  if (ei->hdr.pe.h.Characteristics &
      IMAGE_FILE_EXECUTABLE_IMAGE > 0)
    printf("executable ");

  printf("pe image\n");

  printf("sections                : %08x\n", ei->hdr.pe.h.NumberOfSections);
  printf("size of code            : %08x\n", ei->hdr.pe.opt.SizeOfCode);
  printf("initialized data size   : %08x\n", ei->hdr.pe.opt.SizeOfInitializedData);
  printf("uninitialized data size : %08x\n", ei->hdr.pe.opt.SizeOfUninitializedData);
  printf("entry point             : %08x\n", ei->hdr.pe.opt.AddressOfEntryPoint);
  printf("image base              : %08x\n", ei->hdr.pe.opt.ImageBase);
  printf("code  base              : %08x\n", ei->hdr.pe.opt.BaseOfCode);
  printf("data  base              : %08x\n", ei->hdr.pe.opt.BaseOfData);
  printf("section alignment       : %08x\n", ei->hdr.pe.opt.SectionAlignment);
  printf("file alignment          : %08x\n", ei->hdr.pe.opt.FileAlignment);
  printf("size of image           : %08x\n", ei->hdr.pe.opt.SizeOfImage);
  printf("size of headers         : %08x\n", ei->hdr.pe.opt.SizeOfHeaders);
  printf("checksum                : %08x\n", ei->hdr.pe.opt.CheckSum);

  for (i=0; i < ei->hdr.pe.h.NumberOfSections; i++ ) {
    printf("section name            : %s\n", ei->hdr.pe.section[i].Name);
    printf("virtual address         : %08x\n", ei->hdr.pe.section[i].VirtualAddress);
    printf("size of raw data        : %08x\n", ei->hdr.pe.section[i].SizeOfRawData);
    printf("address of raw data     : %08x\n", ei->hdr.pe.section[i].PointerToRawData);
  }
}

/* context for static data 
 * TODO: make concurrent contexts 
 */
#define MY_CXT_KEY "Stack::_guts" XS_VERSION

typedef struct {
  //cpu
  sreg_t sreg[6];
  reg_t reg[8];
  U32 eflags;
  //housekeeping
  U32 size;
  U32 base;

  executableImage image;
} my_cxt_t;

START_MY_CXT

#line 336 "Stack.c"
XS(XS_Stack_init); /* prototype to pass -Wmissing-prototypes */
XS(XS_Stack_init)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: Stack::init(size_t)");
    {
	U32	size_t = (unsigned long)SvUV(ST(0));
#line 335 "Stack.xs"
	dMY_CXT;
#line 347 "Stack.c"
#line 337 "Stack.xs"
	MY_CXT.size = size_t;
  	(void *)R_EBP = safemalloc(size_t);
	MY_CXT.base = R_EBP;
	(void *)R_ESP = (void *)R_EBP + size_t;
#line 353 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_Stack_cleanup); /* prototype to pass -Wmissing-prototypes */
XS(XS_Stack_cleanup)
{
    dXSARGS;
    if (items != 0)
	Perl_croak(aTHX_ "Usage: Stack::cleanup()");
    {
#line 345 "Stack.xs"
	dMY_CXT;
#line 367 "Stack.c"
#line 347 "Stack.xs"
	Safefree((void *)MY_CXT.base);
	if (MY_CXT.image.data != NULL)
	  Safefree(MY_CXT.image.data);
	(void *)R_EBP = NULL;
#line 373 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_Stack_push32); /* prototype to pass -Wmissing-prototypes */
XS(XS_Stack_push32)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: Stack::push32(val)");
    {
	U32	val = (unsigned long)SvUV(ST(0));
#line 356 "Stack.xs"
	dMY_CXT;
#line 388 "Stack.c"
#line 358 "Stack.xs"
	R_ESP -= sizeof(U32);
	if (R_ESP < MY_CXT.base) {
	  croak("Stack error: buffer overflow (original ebp: %08x ebp: %08x esp:%08x)\n",
		MY_CXT.base, R_EBP, R_ESP);
	}
	*(U32 *)R_ESP = val;
#line 396 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_Stack_pop32); /* prototype to pass -Wmissing-prototypes */
XS(XS_Stack_pop32)
{
    dXSARGS;
    if (items != 0)
	Perl_croak(aTHX_ "Usage: Stack::pop32()");
    {
#line 368 "Stack.xs"
	dMY_CXT;
#line 410 "Stack.c"
	U32	RETVAL;
	dXSTARG;
#line 370 "Stack.xs"
  	RETVAL = *(U32 *)R_ESP;
	R_ESP += sizeof(U32);
	if (R_ESP > (MY_CXT.base + MY_CXT.size)) {
	  croak("Stack error: buffer under-run  (original ebp: %08x ebp: %08x esp:%08x)\n",
		MY_CXT.base, R_EBP, R_ESP);
	}
#line 420 "Stack.c"
	XSprePUSH; PUSHu((UV)RETVAL);
    }
    XSRETURN(1);
}

XS(XS_Registers_get_reg); /* prototype to pass -Wmissing-prototypes */
XS(XS_Registers_get_reg)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: Registers::get_reg(reg)");
    {
	char *	reg = (char *)SvPV_nolen(ST(0));
#line 385 "Stack.xs"
	dMY_CXT;
#line 436 "Stack.c"
	U32	RETVAL;
	dXSTARG;
#line 387 "Stack.xs"
	RETVAL = 0;
	if (strlen(reg) < 2 || strlen(reg) > 3) {
		return;
	}
	switch (reg[1]) {
	case 's':
		switch(reg[0]) {
		case 'e':
			if (strEQ(reg, "es")) {
				RETVAL = SR_ES;
			} else if (strEQ(reg, "esi")) {
				RETVAL = R_ESI;
			} else if (strEQ(reg, "esp")) {
				RETVAL = R_ESP;
			}
			break;
		case 'c':
			RETVAL = SR_CS;
			break;
		case 'd':
			RETVAL = SR_DS;
			break;
		case 'f':
			RETVAL = SR_FS;
			break;
		case 'g':
			RETVAL = SR_GS;
			break;
		case 's':
			RETVAL = SR_SS;
			break;
		default:
			break;
		}
		break;
	case 'a':
		RETVAL = R_EAX;
		break;
	case 'b':
		if (strEQ(reg, "ebx")) {
			RETVAL = R_EBX;
		} else if (strEQ(reg, "ebp")) {
			RETVAL = R_EBP;
		}
		break;
	case 'c':
		RETVAL = R_ECX;
		break;
	case 'd':
		if (strEQ(reg, "edx")) {
			RETVAL = R_EDX;
		} else if (strEQ(reg, "edi")) {
			RETVAL = R_EDI;
		}
		break;
	case 'i':
		switch(reg[0]) {
		case 'e':
			RETVAL = R_EIP;
			break;
		case 's':
			RETVAL = R_SI;
			break;
		case 'd':
			RETVAL = R_DI;
			break;
		default:
			break;
		}
		break;
	case 'x':
		switch (reg[0]) {
		case 'a':
			RETVAL = R_AX;
			break;
		case 'b':
			RETVAL = R_BX;
			break;
		case 'c':
			RETVAL = R_CX;
			break;
		case 'd':
			RETVAL = R_DX;
			break;
		default:
			break;
		}
		break;
	case 'p':
		switch(reg[0]) {
		case 'b':
			RETVAL = R_BP;
			break;
		case 's':
			RETVAL = R_SP;
			break;
		case 'i':
			RETVAL = R_IP;
			break;
		default:
			break;
		}
	case 'h':
		switch(reg[0]) {
		case 'a':
			RETVAL = R_AH;
			break;
		case 'b':
			RETVAL = R_BH;
			break;
		case 'c':
			RETVAL = R_CH;
			break;
		case 'd':
			RETVAL = R_DH;
			break;
		default:
			break;
		}
	case 'l':
		switch(reg[0]) {
		case 'a':
			RETVAL = R_AL;
			break;
		case 'b':
			RETVAL = R_BL;
			break;
		case 'c':
			RETVAL = R_CL;
			break;
		case 'd':
			RETVAL = R_DL;
			break;
		default:
			break;
		}
	default:
		break;
	}	

#line 580 "Stack.c"
	XSprePUSH; PUSHu((UV)RETVAL);
    }
    XSRETURN(1);
}

XS(XS_Registers_set_reg); /* prototype to pass -Wmissing-prototypes */
XS(XS_Registers_set_reg)
{
    dXSARGS;
    if (items != 2)
	Perl_croak(aTHX_ "Usage: Registers::set_reg(reg, val)");
    {
	char *	reg = (char *)SvPV_nolen(ST(0));
	U32	val = (unsigned long)SvUV(ST(1));
#line 535 "Stack.xs"
	dMY_CXT;
#line 597 "Stack.c"
#line 537 "Stack.xs"
	if (strlen(reg) < 2 || strlen(reg) > 3) {
		return;
	}
	switch (reg[1]) {
	case 's':
		switch(reg[0]) {
		case 'e':
			if (strEQ(reg, "es")) {
				SR_ES = val;
			} else if (strEQ(reg, "esi")) {
				R_ESI = val;
			} else if (strEQ(reg, "esp")) {
				R_ESP = val;
			}
			break;
		case 'c':
			SR_CS = val;
			break;
		case 'd':
			SR_DS = val;
			break;
		case 'f':
			SR_FS = val;
			break;
		case 'g':
			SR_GS = val;
			break;
		case 's':
			SR_SS = val;
			break;
		default:
			break;
		}
		break;
	case 'a':
		R_EAX = val;
		break;
	case 'b':
		if (strEQ(reg, "ebx")) {
			R_EBX = val;
		} else if (strEQ(reg, "ebp")) {
			R_EBP = val;
		}
		break;
	case 'c':
		R_ECX;
		break;
	case 'd':
		if (strEQ(reg, "edx")) {
			R_EDX = val;
		} else if (strEQ(reg, "edi")) {
			R_EDI = val;
		}
		break;
	case 'i':
		switch(reg[0]) {
		case 'e':
			R_EIP = val;
			break;
		case 's':
			R_SI = val;
			break;
		case 'd':
			R_DI = val;
			break;
		default:
			break;
		}
		break;
	case 'x':
		switch (reg[0]) {
		case 'a':
			R_AX = val;
			break;
		case 'b':
			R_BX = val;
			break;
		case 'c':
			R_CX = val;
			break;
		case 'd':
			R_DX = val;
			break;
		default:
			break;
		}
		break;
	case 'p':
		switch(reg[0]) {
		case 'b':
			R_BP = val;
			break;
		case 's':
			R_SP = val;
			break;
		case 'i':
			R_IP = val;
			break;
		default:
			break;
		}
	case 'h':
		switch(reg[0]) {
		case 'a':
			R_AH = val;
			break;
		case 'b':
			R_BH = val;
			break;
		case 'c':
			R_CH = val;
			break;
		case 'd':
			R_DH = val;
			break;
		default:
			break;
		}
	case 'l':
		switch(reg[0]) {
		case 'a':
			R_AL = val;
			break;
		case 'b':
			R_BL = val;
			break;
		case 'c':
			R_CL = val;
			break;
		case 'd':
			R_DL = val;
			break;
		default:
			break;
		}
	default:
		break;
	}
#line 737 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_DisAsm_init); /* prototype to pass -Wmissing-prototypes */
XS(XS_DisAsm_init)
{
    dXSARGS;
    if (items != 0)
	Perl_croak(aTHX_ "Usage: DisAsm::init()");
    {
#line 681 "Stack.xs"
	init_sync();
#line 751 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_DisAsm_load_file); /* prototype to pass -Wmissing-prototypes */
XS(XS_DisAsm_load_file)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: DisAsm::load_file(file)");
    {
	char *	file = (char *)SvPV_nolen(ST(0));
#line 687 "Stack.xs"
	dMY_CXT;
#line 766 "Stack.c"
	int	RETVAL;
	dXSTARG;
#line 689 "Stack.xs"
	RETVAL = load(file, &MY_CXT.image);
#line 771 "Stack.c"
	XSprePUSH; PUSHi((IV)RETVAL);
    }
    XSRETURN(1);
}

XS(XS_DisAsm_printFileStats); /* prototype to pass -Wmissing-prototypes */
XS(XS_DisAsm_printFileStats)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: DisAsm::printFileStats(void)");
    {
#line 696 "Stack.xs"
	dMY_CXT;
#line 786 "Stack.c"
#line 698 "Stack.xs"
  	printfstat(&MY_CXT.image);
#line 789 "Stack.c"
    }
    XSRETURN_EMPTY;
}

XS(XS_DisAsm_entryPoint); /* prototype to pass -Wmissing-prototypes */
XS(XS_DisAsm_entryPoint)
{
    dXSARGS;
    if (items != 1)
	Perl_croak(aTHX_ "Usage: DisAsm::entryPoint(self)");
    {
	SV *	self = ST(0);
#line 704 "Stack.xs"
	dMY_CXT;
#line 804 "Stack.c"
	U32	RETVAL;
	dXSTARG;
#line 706 "Stack.xs"
  	RETVAL = MY_CXT.image.base + MY_CXT.image.ep;
#line 809 "Stack.c"
	XSprePUSH; PUSHu((UV)RETVAL);
    }
    XSRETURN(1);
}

XS(XS_DisAsm_disAssemble); /* prototype to pass -Wmissing-prototypes */
XS(XS_DisAsm_disAssemble)
{
    dXSARGS;
    if (items != 2)
	Perl_croak(aTHX_ "Usage: DisAsm::disAssemble(self, offset)");
    {
	SV *	self = ST(0);
	SV *	offset = ST(1);
#line 715 "Stack.xs"
	dMY_CXT;
#line 826 "Stack.c"
	SV *	RETVAL;
#line 717 "Stack.xs"
  	U32 o;
#line 830 "Stack.c"
#line 719 "Stack.xs"
  	o = SvIV(offset);
	RETVAL = newRV((SV *)disAsm(&MY_CXT.image, o));
#line 834 "Stack.c"
	ST(0) = RETVAL;
	sv_2mortal(ST(0));
    }
    XSRETURN(1);
}

#ifdef __cplusplus
extern "C"
#endif
XS(boot_Stack); /* prototype to pass -Wmissing-prototypes */
XS(boot_Stack)
{
    dXSARGS;
    char* file = __FILE__;

    XS_VERSION_BOOTCHECK ;

        newXS("Stack::init", XS_Stack_init, file);
        newXS("Stack::cleanup", XS_Stack_cleanup, file);
        newXS("Stack::push32", XS_Stack_push32, file);
        newXS("Stack::pop32", XS_Stack_pop32, file);
        newXS("Registers::get_reg", XS_Registers_get_reg, file);
        newXS("Registers::set_reg", XS_Registers_set_reg, file);
        newXS("DisAsm::init", XS_DisAsm_init, file);
        newXS("DisAsm::load_file", XS_DisAsm_load_file, file);
        newXS("DisAsm::printFileStats", XS_DisAsm_printFileStats, file);
        newXS("DisAsm::entryPoint", XS_DisAsm_entryPoint, file);
        newXS("DisAsm::disAssemble", XS_DisAsm_disAssemble, file);

    /* Initialisation Section */

#line 329 "Stack.xs"
  MY_CXT_INIT;

#line 869 "Stack.c"

    /* End of Initialisation Section */

    XSRETURN_YES;
}

