/*
 *  packages: Stack Registers DisAsm
 *
 *  Nate Lally  nate[at]airitechsecurity[dot]com
 *
 *  Changelog: 
 *
 *  6/24/04
 *    -corrected ordinal interpretation in pe loader
 *
 *  6/23/04
 *    -fixed a memory leak
 *    -implemented reading of import lookup tables
 *  6/10/04
 *
 *  6/8/04
 *    -fixed export and import sections in pe loader
 *  6/7/04
 *    -yet again re-wrote image_file structure
 *     this time, i read an article on the elf structure first
 *    -wrote detect_image_type (used to be part of load_image)
 *    -offloaded image type stuff to image.h
 *  6/4/04
 *    -re-wrote image_file structure, load_image, printfstat
 *    -added error checking to load_image
 *  6/2/04
 *    -created instruction lookup hash callback
 *     mechanism
 *    -created script to output hash table and
 *     sub execINS{} skeleton.. 251 x86 instructions
 *    -re-wrote Registers.pm (arguements, oo methods, 
 *     working nextkey, return type)
 *    -re-wrote push32 & pop32 as object methods
 *    -implemented module wide io/display/error-handling
 *	routines $self->{LOG_LEVEL} based from stdafx.h
 * 
 *  sometime during may
 *    -wrote DisAsm
 *    -wrote PE loader
 *    -wrote Register routines
 *    -wrote Stack routines
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
#include "image.h"
#include <sys/types.h>

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

/* context for static data 
 * TODO: make concurrent contexts 
 */
#define MY_CXT_KEY "Stack::_guts" XS_VERSION

typedef struct {
  //cpu
  sreg_t sreg[6];
  reg_t reg[8];
  U32 eflags;

  struct {
    void *base;
    U32 size;
  } stack;

  image_file image;

  HV *size2bits, *bits2size;
} my_cxt_t;

START_MY_CXT

/*  annotated mess of macros that is to call
 *    a perl method
 ******************************************/
static void
loglvl_callback(SV *self, char *loglvl, char *method, SV *msg)
{
  dSP; //declare local copy of perl stack pointer
  SV *key, *func;
  HE *he;

  key = newSVpv(loglvl, strlen(loglvl));
  if (hv_exists_ent((HV *)SvRV(self), key, 0)) {
    he = hv_fetch_ent((HV *)SvRV(self), key, 0, 0);
    
    if (SvTYPE(SvRV(HeVAL(he))) == SVt_PVCV) {

      ENTER;	//mark stack pointer for garbage
      SAVETMPS; //set flag on stack
      
      PUSHMARK(SP); //save stack pointer
      func = sv_newmortal();
      if (method != NULL)
        sv_setpvf(func, method);

      XPUSHs(sv_2mortal(msg));
      XPUSHs(func);
      PUTBACK; //copy local stack to global

      call_sv(SvRV(HeVAL(he)), G_DISCARD);

      FREETMPS; //collect garbage
      LEAVE; //remove mark

    } else {
    printf("(not pvcv) message from:'%s' lvl:'%s' test:'%s' ignored\n",
	   SvPV_nolen(self), loglvl, SvPV_nolen(msg));
    }
  } else {
    printf("(not exists) message from:'%s' lvl:'%s' test:'%s' ignored\n",
	   SvPV_nolen(self), loglvl, SvPV_nolen(msg));
  }
}

/*  disAsm:  interface to ndisasm
 *
 *    -performs bounds checking, error reporting
 *    -operates on image loaded by loadImage
 *
 *  returns: hash value with keys: 
 *    err, errstr - errno & error string
 *    len - number of bytes dis-assembled (guaranteed != 0)
 *    bytes - opcode bytes
 *    nasm - nasm syntax assembler code string
 ****************************************************/
static HV *
disAsm(image_file *img, U32 offset)
{
  U8 i;
  U32 relOff;
  unsigned char *pos;
  char outbuf[256];
  unsigned long lendis = 0;
  HV *ret;
  AV *bytes;

  /* prefer refers to intel, amd, cyrix, idt, winchip
   */
  int segsize = 32, lenread = 0, prefer = 0;

  ret = (HV *)sv_2mortal((SV *)newHV());
  hv_store_ent(ret, newSVpvf("err"), newSViv(0), 0);

  relOff = offset - img->base_preferred;
  if ( relOff < 0 || relOff > img->size ) {
    hv_store_ent(ret, newSVpvf("err"), newSViv(-1), 0);
    hv_store_ent(ret, newSVpvf("errstr"), 
       newSVpvf("invalid offset '%08x' (start %08x, end %08x)",
		offset, img->base_preferred, img->base_preferred + img->size), 0);
    return ret;
  }

  //  nextsync = next_sync (offset, &synclen);

  pos = img->base + relOff;

  lendis = disasm(pos, outbuf, segsize, offset, FALSE, prefer);

  bytes = (AV *)sv_2mortal((SV *)newAV());

  if (!lendis) {
    lendis = eatbyte(pos, outbuf);
    hv_store_ent(ret, newSVpvf("err"), newSViv(1), 0);
    hv_store_ent(ret, newSVpvf("errstr"), 
	     newSVpvf("ate byte at %08x", offset), 0);
  }

  hv_store_ent(ret, newSVpvf("len"), newSViv(lendis), 0);

  for (i=0; i<lendis; i++) {
    av_push(bytes, newSViv(*(U8 *)(pos + i)));
  }
  hv_store_ent(ret, newSVpvf("bytes"), newRV((SV *)bytes), 0);
  hv_store_ent(ret, newSVpvf("sz"), newSVpv(outbuf, strlen(outbuf)), 0);

  return ret;
}

/*  convert relative virtual address in pe to file
 *    offset.  fine which section rva is in, re-base 
 *******************************************************/
u_int32_t
rva2offset(u_int32_t rva, image_file *img) {
  U8 i;
  for (i = 0; i < img->pe.h.number_of_Sections; i++) {
    if (rva >= img->pe.section[i].relative_virtual_address
	&& rva < (img->pe.section[i].relative_virtual_address
		  + img->pe.section[i].virtual_size)) {

      rva -= img->pe.section[i].relative_virtual_address;
      rva += img->pe.section[i].offset_in_file;
      return rva;
    }
  }
  return -1;
}

char *
freadasciiz(FILE *fh)
{
  char *out;
  void *inp, *orig;
  U8 i = 0;

  orig = inp = alloca(80);

  while (*(char *)inp != 0x0) {
    fread(inp++, 1, 1, fh);
    i++;
  }
  out = (char *)safemalloc(i + 1);
  strcpy(out, (char *)orig);
  return out;
}

/* detect_image_type:  determines the image format
 * 
 * returns: enum _image_type
 *   corresponds to the now (if not already) open file handle
 *************************************************************/
enum image_type
detect_image_type(char *file)
{
  u_int8_t i;
  u_int32_t offset;
  FILE *fh;
  enum image_type type = IMAGE_UNKNOWN;
  void *buf = alloca(8);

  fh = fopen(file, "rb");
  if (fh == NULL) return IMAGE_NONE;

  for (i = 0; image_type_db[i].type != IMAGE_LAST; i++) {
    //determine signiture location
    if (image_type_db[i].offset_pointer) {
      fseek(fh, image_type_db[i].offset_pointer, SEEK_SET);
      fread(&offset, sizeof(offset), 1, fh);
    } else
      offset = image_type_db[i].offset; 

    //read signiture from file
    fseek(fh, offset, SEEK_SET);
    fread(buf, image_type_db[i].size, 1, fh);

    //TODO now would be a good time to check system's endianness
    //compare signiture to buffer
    if (memcmp(buf, image_type_db[i].signature,
	       image_type_db[i].size) == 0) {
      type = image_type_db[i].type;
      //returning here would prevent detection of nested formats
    }
    //play nice with our fh
    rewind(fh);
  }
  fclose(fh);
  return type;
}

/*  load:  detects type and loads file
 *
 *  returns: -4 seek past end of file (malformed header)
 *           -3 fread size error (corrupt file)
 *           -2 header type not known
 *           -1 file open failure
 *            0 load successful
 *
 *  TODO: support executable formats other than PE
 ****************************************************/
#define myread(dst, t, n, fh) {if (fread(dst, t, n, fh) != n)\
      {fclose(fh); return -3;} }
#define myseek(fh, pos) {if (fseek(fh, pos, SEEK_SET) == EOF)\
      {fclose(fh); return -4;} }
int
load_image(char *file, image_file *img)
{
  int i, ret = 0;
  FILE *fh;

  fh = fopen(file, "rb");
  if (fh == NULL) return -1;

  img->name = (char *)safemalloc(strlen(file) + 1);
  strcpy(img->name, file);

  switch (img->type) {
  case IMAGE_PE:
    myread((void *)&img->mz, sizeof(img->mz), 1, fh);
    myseek(fh, img->mz.new_hdr_offset);
    myread((void *)&img->pe.h, sizeof(img->pe.h), 1, fh);

    img->entry_point = img->pe.h.entry_point_RVA;
    img->base_preferred = img->pe.h.base_of_image;
    img->size = img->pe.h.size_of_image;

    //avoiding mmap
    img->base = safemalloc(img->size);
    memset(img->base, 0, img->size);

    //load section headers
    myread((void *)&img->pe.section, sizeof(img->pe.section[0]),
	   img->pe.h.number_of_Sections, fh);

    //load sections
    for (i=0; i < img->pe.h.number_of_Sections; i++ ) {
      myseek(fh, img->pe.section[i].offset_in_file);
      myread(img->base + img->pe.section[i].relative_virtual_address,
	     img->pe.section[i].size_in_file, 1, fh);
    }

    //re-base export table pointers
    img->pe.export_d = img->base + img->pe.h.export_table_RVA;
    img->pe.export_address_t =  img->base + img->pe.export_d->address_table;
    img->pe.export_name_t = img->base + img->pe.export_d->name_pointers;
    img->pe.export_ordinal_t = img->base + img->pe.export_d->ordinal_table;

    //more re-basing
    img->pe.import_d = img->pe.import = img->base + img->pe.h.import_table_RVA;
    img->pe.resource_d = img->base + img->pe.h.resource_table_RVA;
    img->pe.tls_d = img->base + img->pe.h.thread_local_storage_table_RVA;
    break;
  case IMAGE_UNKNOWN:
  default:  ret = -2; break;
  }

  fclose(fh);
  return ret;
}

void
printfstat(image_file *img)
{
  int i;
  u_int32_t *a = NULL;
  printf("image name      : %s\n", img->name );
  printf("image type      : %s\n", image_type_name[img->type].name );
  printf("description     : %s\n", image_type_name[img->type].description );

  switch(img->type) {
  case IMAGE_PE:
    printf("characteristics : ");
    (img->pe.h.flags & IMAGE_FILE_DEBUG_STRIPPED) &&
      printf("stripped ");
  
    (img->pe.h.flags & IMAGE_FILE_RELOCS_STRIPPED) &&
      printf("non-relocatable ") || printf("relocatable ");

    (img->pe.h.flags & IMAGE_FILE_EXECUTABLE_IMAGE) &&
      printf("executable ");
    
    (img->pe.h.flags & IMAGE_FILE_DLL) &&
      printf("dynamic library ");
    printf("\n");

    printf("cpu type                : %08x\n", img->pe.h.CPU_Type);
    printf("linker version          : %08x\n", img->pe.h.Linker_version);
    printf("OS version major        : %08x\n", img->pe.h.OS_version_major);
    printf("  minor                 : %08x\n", img->pe.h.OS_version_major);
    printf("size of code            : %08x\n", img->pe.h.size_of_code);
    printf("initialized data size   : %08x\n", img->pe.h.size_of_init_data);
    printf("uninitialized data size : %08x\n", img->pe.h.size_of_uninit_data);
    printf("entry point             : %08x\n", img->pe.h.entry_point_RVA);
    printf("image base              : %08x\n", img->pe.h.base_of_image);
    printf("code  base              : %08x\n", img->pe.h.base_of_code);
    printf("data  base              : %08x\n", img->pe.h.base_of_data);
    printf("section alignment       : %08x\n", img->pe.h.image_alignment);
    printf("file alignment          : %08x\n", img->pe.h.file_alignment);
    printf("size of image           : %08x\n", img->pe.h.size_of_image);
    printf("size of headers         : %08x\n", img->pe.h.size_of_header);
    printf("checksum                : %08x\n", img->pe.h.file_CRC);
    printf("stack reserve           : %u\n", img->pe.h.stack_reserve);
    printf("stack commit            : %u\n", img->pe.h.stack_commit);
    printf("heap reserve            : %u\n", img->pe.h.heap_reserve);
    printf("heap commit             : %u\n", img->pe.h.heap_commit);

    printf("export table            : %08x\n", img->pe.h.export_table_RVA);
    printf("table size              : %08x\n", img->pe.h.export_table_size);
    printf("import table            : %08x\n", img->pe.h.import_table_RVA);
    printf("table size              : %08x\n", img->pe.h.import_table_size);
    printf("resource table          : %08x\n", img->pe.h.resource_table_RVA);
    printf("table size              : %08x\n", img->pe.h.resource_table_size);
    printf("reloc table             : %08x\n", img->pe.h.reloc_table_RVA);
    printf("table size              : %08x\n", img->pe.h.reloc_table_size);
    printf("debug table             : %08x\n", img->pe.h.debug_table_RVA);
    printf("table size              : %08x\n", img->pe.h.debug_table_size);
    printf("thread local storage tbl: %08x\n", img->pe.h.thread_local_storage_table_RVA);
    printf("table size              : %08x\n", img->pe.h.thread_local_storage_table_size);
    printf("bound import table      : %08x\n", img->pe.h.bound_import_table_RVA);
    printf("table size              : %08x\n", img->pe.h.bound_import_table_size);
    printf("IAT table               : %08x\n", img->pe.h.IAT_table_RVA);
    printf("table size              : %08x\n", img->pe.h.IAT_table_size);
    printf("delay import desc table : %08x\n", img->pe.h.delay_import_desc_table_RVA);
    printf("table size              : %08x\n", img->pe.h.delay_import_desc_table_size);

    printf("number of sections      : %08x\n", img->pe.h.number_of_Sections);
    for (i=0; i < img->pe.h.number_of_Sections; i++ ) {
      printf("section name            : %s\n", img->pe.section[i].name);
      printf("virtual address         : %08x\n", img->pe.section[i].relative_virtual_address);
      printf("size of raw data        : %08x\n", img->pe.section[i].size_in_file);
      printf("address of raw data     : %08x\n", img->pe.section[i].offset_in_file);
      img->pe.section[i].file_offset_to_relocs &&
      printf("address of relocs       : %08x\n", img->pe.section[i].file_offset_to_relocs);
      img->pe.section[i].number_of_relocs &&
      printf("number of relocs        : %u\n", img->pe.section[i].number_of_relocs);
      img->pe.section[i].file_offset_to_line_numbers &&
      printf("address of line numbers : %08x\n", img->pe.section[i].file_offset_to_line_numbers);
      img->pe.section[i].number_of_line_numbers &&
      printf("number of line numbers  : %u\n", img->pe.section[i].number_of_line_numbers);
    }

    printf("\n");
    printf("export section\n");
    printf("export image name       : %s\n", (char *)(img->base + img->pe.export_d->name));
    printf("number of functions     : %u\n", img->pe.export_d->address_table_count);
    printf("  named functions       : %u\n", img->pe.export_d->name_pointers_count);
    printf("  RVA    | Ordinal  | Name\n");

    //walk the export table arrays
    for (img->pe.export_address = img->pe.export_address_t,
	   img->pe.export_name = img->pe.export_name_t,
	   img->pe.export_ordinal = img->pe.export_ordinal_t;

	 (void *)img->pe.export_address < 
	   ((void *)img->pe.export_address_t + img->pe.export_d->address_table_count * 4);

	 img->pe.export_address++,
	   img->pe.export_name++,
	   img->pe.export_ordinal++)  {

      printf("%08x | %08x | %s\n",
	     *img->pe.export_address,
	     *img->pe.export_ordinal + img->pe.export_d->ordinal_base,
	     (char *)(*img->pe.export_name + img->base_actual));
    }

    printf("\nimport section\n");
    for (img->pe.import = img->pe.import_d;
	 ((void *)img->pe.import < (void *)img->pe.import_d + img->pe.h.import_table_size)
	   && (strlen((char *)(img->base + img->pe.import->name)) > 0);
	 img->pe.import++) {
      printf("import name             : %s\n", (char *)(img->base + img->pe.import->name));
      printf("import address table rva: %08x\n", (img->pe.import->import_address_table));
      printf("import lookup table rva : %08x\n", (img->pe.import->import_lookup_table));
      (img->pe.import->forwarder_chain) &&
      printf("    forwarder chain rva : %08x\n", (img->pe.import->forwarder_chain));

      //walk image lookup table
      a = img->base + img->pe.import->import_lookup_table;
      if (IMAGE_SNAP_BY_ORDINAL(*a))
	printf("Function | Ordinal\n");
      else
	printf("Function | Name\n");
      do {
	printf("%08x | ", ((PIMAGE_THUNK_DATA)a)->u1.Function);
	if (IMAGE_SNAP_BY_ORDINAL(*a))
	  printf("%08x\n", IMAGE_ORDINAL((DWORD)((PIMAGE_THUNK_DATA)a)->u1.AddressOfData->Name));
	else
	  printf("%s\n", (char *)(img->base_actual + ((PIMAGE_THUNK_DATA)a)->u1.AddressOfData->Name));
	
      } while (*(++a));
      printf("\n");
    }
    break;
  case IMAGE_NONE:
  case IMAGE_OMF:
  case IMAGE_COFF:
  case IMAGE_MZ:
  case IMAGE_AOUT:
  case IMAGE_ELF:
  case IMAGE_BIN:
  case IMAGE_TEXT:
  case IMAGE_UNKNOWN:
  default:
    printf("TODO: Implement this format loader.\n");
    break;
  }
}

/********************************************************************/

MODULE = VirtualMachine         PACKAGE = Stack

void
alloc(self)
  SV *self;
  PREINIT:
	dMY_CXT;
	HE *size;
  CODE:
        size = hv_fetch_ent((HV *)SvRV(self), newSVpvf("SIZE"), 0, 0);
	
	MY_CXT.stack.size = SvIV(HeVAL(size));
  	MY_CXT.stack.base = safemalloc(MY_CXT.stack.size);
	(void *)R_EBP = MY_CXT.stack.base;
	R_ESP = R_EBP + MY_CXT.stack.size;

void
cleanup(self)
  SV *self;
  PREINIT:
	dMY_CXT;
  CODE:
	Safefree(MY_CXT.stack.base);
	R_EBP = 0; R_ESP = 0;

void
push32(self, val)
  SV *self
  SV *val
  PREINIT:
	dMY_CXT;
  	SV *ret, *key, *msg;
	HE *he;
	int is_on = 0;
  CODE:
	R_ESP -= sizeof(U32);

	if (R_ESP < (U32)MY_CXT.stack.base) {
	  msg = newSVpvf("buffer overflow (stack base: %08x ebp: %08x esp:%08x)",
			 MY_CXT.stack.base, R_EBP, R_ESP);
	  loglvl_callback(self, "ERR", "push32", msg);
	} else
	  *(U32 *)R_ESP = SvIV(val);

void
pop32(self)
  SV *self
  PREINIT:
	dMY_CXT;
	SV *ret, *msg;
	HE *he;
  PPCODE:
	ret = sv_newmortal();
  	sv_setiv(ret, *(U32 *)R_ESP);
	R_ESP += sizeof(U32);

	if (R_ESP > ((U32)MY_CXT.stack.base + MY_CXT.stack.size)) {
	  msg = newSVpvf( "buffer under-run  (stack base: %08x ebp: %08x esp:%08x)",
			  MY_CXT.stack.base, R_EBP, R_ESP);
	  loglvl_callback(self, "ERR", "pop32", msg);
	}
	XPUSHs(ret);

MODULE = VirtualMachine         PACKAGE = Registers

U32
get_reg(reg)
  char	*reg
  PREINIT:
	dMY_CXT;
  CODE:
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
  	
  OUTPUT:
	RETVAL

void
set_reg(reg, val)
  char	*reg
  U32	 val
  PREINIT:
	dMY_CXT;
  CODE:
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

MODULE = VirtualMachine         PACKAGE = DisAsm

SV *
loadImage(self, file)
  SV *self
  SV *file
  PREINIT:
     dMY_CXT;
     HV *ret;
     SV *msg;
     int err;
     char *szFile;
  CODE:
     err = 0;
     ret = (HV *)sv_2mortal((SV *)newHV());

     if (SvPOK(file)) {
       szFile = SvPV_nolen(file);
       MY_CXT.image.type = detect_image_type(szFile);
       err = load_image(szFile, &MY_CXT.image);
     } else {
       err = 1;
     }

     switch (err) {
     case 0:
       msg = newSVpvf("loaded image '%s'", szFile); break;
     case 1:
       msg = newSVpvf("no file specified", szFile); break;
     case -1:
       msg = newSVpvf("couldn't open file '%s'", szFile); break;
     case -2:
       msg = newSVpvf("type not known for '%s'", szFile); break;
     case -3:
       msg = newSVpvf("'%s' is corrupted, read failure", szFile); break;
     case -4:
       msg = newSVpvf("malformed header in '%s', seek failure", szFile); break;
     default:
       msg = newSVpvf("unknown error loading image '%s'", szFile); break;
     }

     if (err) {
       loglvl_callback(self, "ERR", "loadImage", msg);
     } else {
       loglvl_callback(self, "NOTICE", NULL, msg);
     }
     RETVAL = newRV((SV *)ret);
  OUTPUT:
     RETVAL

void
printFileStats(self)
  SV *self;
  PREINIT:
	dMY_CXT;
  CODE:
  	printfstat(&MY_CXT.image);

U32
entryPoint(self)
  SV *self;
  PREINIT:
	dMY_CXT;
  CODE:
  	RETVAL = MY_CXT.image.base_preferred + MY_CXT.image.entry_point;
  OUTPUT:
	RETVAL

SV *
disAssemble(self, offset)
  SV *self;
  SV *offset;
  PREINIT:
	dMY_CXT;
  	U32 off;
  CODE:
  	off = SvIV(offset);
	RETVAL = newRV((SV *)disAsm(&MY_CXT.image, off));
  OUTPUT:
	RETVAL

void
cleanup(self)
  SV *self;
  PREINIT:
	dMY_CXT;
  CODE:
  	if (MY_CXT.image.name != NULL)
  	  Safefree(MY_CXT.image.name);
	if (MY_CXT.image.base != NULL)
	  Safefree(MY_CXT.image.base);

MODULE = VirtualMachine		PACKAGE = VirtualMachine

BOOT:
  MY_CXT_INIT;
  MY_CXT.image.name = MY_CXT.image.base = NULL;
  MY_CXT.image.type = IMAGE_NONE;
  MY_CXT.size2bits = (HV *)sv_2mortal((SV *)newHV());
  MY_CXT.bits2size = (HV *)sv_2mortal((SV *)newHV());
  hv_store(MY_CXT.size2bits, "byte", 4, newSViv(8), 0);
  hv_store(MY_CXT.size2bits, "word", 4, newSViv(16), 0);
  hv_store(MY_CXT.size2bits, "dword", 5, newSViv(32), 0);
  hv_store(MY_CXT.size2bits, "qword", 5, newSViv(64), 0);
  hv_store(MY_CXT.size2bits, "tword", 5, newSViv(80), 0);
  hv_store_ent(MY_CXT.bits2size, newSViv(0x08), newSVpvf("byte"), 0);
  hv_store_ent(MY_CXT.bits2size, newSViv(0x10), newSVpvf("word"), 0);
  hv_store_ent(MY_CXT.bits2size, newSViv(0x20), newSVpvf("dword"), 0);
  hv_store_ent(MY_CXT.bits2size, newSViv(0x40), newSVpvf("qword"), 0);
  hv_store_ent(MY_CXT.bits2size, newSViv(0x50), newSVpvf("tword"), 0);
  init_sync();

void
size_bits_2way(val)
  SV *val;
  PREINIT:
	dMY_CXT;
	HV *lookup;
	HE *he;
	SV *ret;
  PPCODE:
	ret = sv_newmortal();
	switch (SvTYPE(SvRV(val))) {
	  case SVt_IV: lookup = MY_CXT.size2bits; break;
	  case SVt_PV: lookup = MY_CXT.bits2size; break;
	  default: XPUSHs(ret); return;
	}
	he = hv_fetch_ent(lookup, val, 0, 0);
	ret = sv_2mortal(HeVAL(he));
	XPUSHs(ret);

void
dword(offset)
  SV *offset;
  PREINIT:
	dMY_CXT;
	SV *ret;
	U32 off;
  PPCODE:
	off = SvIV(offset) - MY_CXT.image.base_preferred;
	ret = sv_newmortal();
	if (off > 0 && off < MY_CXT.image.size)
	  sv_setiv(ret, *(U32 *)(MY_CXT.image.base + off));
	XPUSHs(ret);

void
word(offset)
  SV *offset;
  PREINIT:
	dMY_CXT;
	SV *ret;
	U32 off;
  PPCODE:
	off = SvIV(offset) - MY_CXT.image.base_preferred;
	ret = sv_newmortal();
	if (off > 0 && off < MY_CXT.image.size)
	  sv_setiv(ret, *(U16 *)(MY_CXT.image.base + off));
	XPUSHs(ret);

void
byte(offset)
  SV *offset;
  PREINIT:
	dMY_CXT;
	SV *ret;
	U32 off;
  PPCODE:
	off = SvIV(offset) - MY_CXT.image.base_preferred;
	ret = sv_newmortal();
	if (off > 0 && off < MY_CXT.image.size)
	  sv_setiv(ret, *(U8 *)(MY_CXT.image.base + off));
	XPUSHs(ret);

