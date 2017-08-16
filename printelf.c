/*
 * $Id: printelf.c,v 1.52 2017/08/16 23:42:30 urs Exp $
 *
 * Read an ELF file and print it to stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <elf.h>

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [-hv] file...\n", name);
}

static void print_file(const char *filename);
static void print_elf_header(const Elf32_Ehdr *e);
static void print_program_header_table(const Elf32_Ehdr *e);
static void print_section_header_table(const Elf32_Ehdr *e);

static void print_section(const Elf32_Ehdr *e, unsigned int section);
static void print_symtab(const Elf32_Ehdr *e, const Elf32_Shdr *sh);
static void print_relocation(const Elf32_Ehdr *e, const Elf32_Shdr *sh);
static void print_strtab(const Elf32_Ehdr *e, const Elf32_Shdr *sh);
static void print_dynamic(const Elf32_Ehdr *e, const Elf32_Shdr *sh);
static void print_other(const Elf32_Ehdr *e, const Elf32_Shdr *sh);

static char *ph_type_name(unsigned int type);
static char *section_type_name(unsigned int type);
static char *reloc_type_name(unsigned int type);
static void set_relocation(unsigned int machine);

static char *load_file(const char *filename);
static void dump(const void *s, size_t size);
static size_t min(size_t a, size_t b);

/* MSB/LSB conversion routines */

static unsigned char host_endianness(void);
static void conv(Elf32_Ehdr *e);
static void conv_elfheader(Elf32_Ehdr *e);
static void conv_programheader(Elf32_Ehdr *e, Elf32_Phdr *ph);
static void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *sh);
static void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *sh);
static void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *sh);
static void conv_dynamic(Elf32_Ehdr *e, Elf32_Shdr *sh);

int main(int argc, char **argv)
{
    int c;

    if (host_endianness() == ELFDATANONE) {
	fprintf(stderr, "Unknown host endianness\n");
	exit(1);
    }

    while ((c = getopt(argc, argv, "hv")) != -1) {
	switch (c) {
	case 'v':
	    break;
	case '?':
	case 'h':
	    usage(argv[0]);
	    exit(1);
	}
    }
    for (; optind < argc; optind++)
	print_file(argv[optind]);

    return 0;
}

#define ASIZE(a) (sizeof(a)/sizeof(*a))

#define ET(s) [ET_ ## s] = #s
static char *const elf_file_type[] = {
    ET(NONE),  ET(REL),  ET(EXEC),  ET(DYN),
    ET(CORE),
};
#define NFTYPES ASIZE(elf_file_type)

#define PT(s) [PT_ ## s] = #s
static char *const program_header_type_names[] = {
    PT(NULL),  PT(LOAD),   PT(DYNAMIC),  PT(INTERP),
    PT(NOTE),  PT(SHLIB),  PT(PHDR),
};
#define NPTYPES ASIZE(program_header_type_names)

#define SHT(s) [SHT_ ## s] = #s
static char *const section_type_names[] = {
    SHT(NULL),   SHT(PROGBITS), SHT(SYMTAB),  SHT(STRTAB),
    SHT(RELA),   SHT(HASH),     SHT(DYNAMIC), SHT(NOTE),
    SHT(NOBITS), SHT(REL),      SHT(SHLIB),   SHT(DYNSYM),
};
#define NSTYPES ASIZE(section_type_names)

#define DT(s) [DT_ ## s] = #s
static char *const tag_name[] = {
    DT(NULL),     DT(NEEDED),  DT(PLTRELSZ), DT(PLTGOT),
    DT(HASH),     DT(STRTAB),  DT(SYMTAB),   DT(RELA),
    DT(RELASZ),   DT(RELAENT), DT(STRSZ),    DT(SYMENT),
    DT(INIT),     DT(FINI),    DT(SONAME),   DT(RPATH),
    DT(SYMBOLIC), DT(REL),     DT(RELSZ),    DT(RELENT),
    DT(PLTREL),   DT(DEBUG),   DT(TEXTREL),  DT(JMPREL),
};
#define NTAGS ASIZE(tag_name)

#define STB(s) [STB_ ## s] = #s
static char *const symbol_bind[] = {
    STB(LOCAL), STB(GLOBAL), STB(WEAK),
};

#define STT(s) [STT_ ## s] = #s
static char *const symbol_type[] = {
    STT(NOTYPE), STT(OBJECT), STT(FUNC), STT(SECTION),
    STT(FILE),
};

#define EM(s) [EM_ ## s] = #s
static char *const machine_name[] = {
    EM(NONE),         /* No machine */
    EM(M32),          /* AT&T WE 32100 */
    EM(SPARC),        /* SUN SPARC */
    EM(386),          /* Intel 80386 */
    EM(68K),          /* Motorola m68k family */
    EM(88K),          /* Motorola m88k family */

    EM(860),          /* Intel 80860 */
    EM(MIPS),         /* MIPS R3000 big-endian */
    EM(S370),         /* Amdahl */
    EM(MIPS_RS3_LE),  /* MIPS R3000 little-endian */

    EM(PARISC),       /* HPPA */

    EM(VPP500),       /* Fujitsu VPP500 */
    EM(SPARC32PLUS),  /* Sun's "v8plus" */
    EM(960),          /* Intel 80960 */
    EM(PPC),          /* PowerPC */
    EM(PPC64),        /* PowerPC 64 bit */
    EM(S390),         /* IBM S390 */

    EM(V800),         /* NEC V800 series */
    EM(FR20),         /* Fujitsu FR20 */
    EM(RH32),         /* TRW RH32 */
    EM(RCE),          /* Motorola RCE */
    EM(ARM),          /* ARM */
    EM(FAKE_ALPHA),   /* Digital Alpha */
    EM(SH),           /* Hitachi SH */
    EM(SPARCV9),      /* SPARC v9 64-bit */
    EM(TRICORE),      /* Siemens Tricore */
    EM(ARC),          /* Argonaut RISC Core */
    EM(H8_300),       /* Hitachi H8/300 */
    EM(H8_300H),      /* Hitachi H8/300H */
    EM(H8S),          /* Hitachi H8S */
    EM(H8_500),       /* Hitachi H8/500 */
    EM(IA_64),        /* Intel Merced */
    EM(MIPS_X),       /* Stanford MIPS-X */
    EM(COLDFIRE),     /* Motorola Coldfire */
    EM(68HC12),       /* Motorola M68HC12 */
    EM(MMA),          /* Fujitsu MMA */

    EM(X86_64),       /* AMD x86-64 */
};
#define NMTYPES ASIZE(machine_name)

#ifndef R_386_PC16
#define R_386_PC16 21
#endif
#define R(s) [R_386_ ## s] = "386_" #s
static char *const reloc_types_386[] = {
    R(NONE),     R(32),     R(PC32),     R(GOT32),
    R(PLT32),    R(COPY),   R(GLOB_DAT), R(JMP_SLOT),
    R(RELATIVE), R(GOTOFF), R(GOTPC),
    R(PC16),
};
#undef R

#define R(s) [R_X86_64_ ## s] = "X86_64_" #s
static char *const reloc_types_X86_64[] = {
    R(NONE),       R(64),        R(PC32),            R(GOT32),
    R(PLT32),      R(COPY),      R(GLOB_DAT),        R(JUMP_SLOT),
    R(RELATIVE),   R(GOTPCREL),  R(32),              R(32S),
    R(16),         R(PC16),      R(8),               R(PC8),
    R(DTPMOD64),   R(DTPOFF64),  R(TPOFF64),         R(TLSGD),
    R(TLSLD),      R(DTPOFF32),  R(GOTTPOFF),        R(TPOFF32),
    R(PC64),       R(GOTOFF64),  R(GOTPC32),         R(GOT64),
    R(GOTPCREL64), R(GOTPC64),   R(GOTPLT64),        R(PLTOFF64),
    R(SIZE32),     R(SIZE64),    R(GOTPC32_TLSDESC), R(TLSDESC_CALL),
    R(TLSDESC),    R(IRELATIVE), R(RELATIVE64),
};
#undef R

#ifndef R_SPARC_GLOB_JMP
#define R_SPARC_GLOB_JMP 42
#endif
#define R(s) [R_SPARC_ ## s] = "SPARC_" #s
static char *const reloc_types_SPARC[] = {
    R(NONE),     R(8),        R(16),       R(32),
    R(DISP8),    R(DISP16),   R(DISP32),   R(WDISP30),
    R(WDISP22),  R(HI22),     R(22),       R(13),
    R(LO10),     R(GOT10),    R(GOT13),    R(GOT22),
    R(PC10),     R(PC22),     R(WPLT30),   R(COPY),
    R(GLOB_DAT), R(JMP_SLOT), R(RELATIVE), R(UA32),

    /* Additional Sparc64 relocs. */

    R(PLT32),    R(HIPLT22),  R(LOPLT10),  R(PCPLT32),
    R(PCPLT22),  R(PCPLT10),  R(10),       R(11),
    R(64),       R(OLO10),    R(HH22),     R(HM10),
    R(LM22),     R(PC_HH22),  R(PC_HM10),  R(PC_LM22),
    R(WDISP16),  R(WDISP19),  R(GLOB_JMP), R(7),
    R(5),        R(6),        R(DISP64),   R(PLT64),
    R(HIX22),    R(LOX10),    R(H44),      R(M44),
    R(L44),      R(REGISTER), R(UA64),     R(UA16),
};
#undef R

#ifndef R_PPC_ADDR30
#define R_PPC_ADDR30 37
#endif
#define R(s) [R_PPC_ ## s] = "PPC_" #s
static char *const reloc_types_PPC[] = {
    R(NONE),           R(ADDR32),          R(ADDR24),     R(ADDR16),
    R(ADDR16_LO),      R(ADDR16_HI),       R(ADDR16_HA),  R(ADDR14),
    R(ADDR14_BRTAKEN), R(ADDR14_BRNTAKEN), R(REL24),      R(REL14),
    R(REL14_BRTAKEN),  R(REL14_BRNTAKEN),  R(GOT16),      R(GOT16_LO),
    R(GOT16_HI),       R(GOT16_HA),        R(PLTREL24),   R(COPY),
    R(GLOB_DAT),       R(JMP_SLOT),        R(RELATIVE),   R(LOCAL24PC),
    R(UADDR32),        R(UADDR16),         R(REL32),      R(PLT32),
    R(PLTREL32),       R(PLT16_LO),        R(PLT16_HI),   R(PLT16_HA),
    R(SDAREL16),       R(SECTOFF),         R(SECTOFF_LO), R(SECTOFF_HI),
    R(SECTOFF_HA),     R(ADDR30),
};
#undef R

#define R(s) [R_68K_ ## s] = "68K_" #s
static char *const reloc_types_68K[] = {
    R(NONE),     R(32),       R(16),       R(8),
    R(PC32),     R(PC16),     R(PC8),      R(GOT32),
    R(GOT16),    R(GOT8),     R(GOT32O),   R(GOT16O),
    R(GOT8O),    R(PLT32),    R(PLT16),    R(PLT8),
    R(PLT32O),   R(PLT16O),   R(PLT8O),    R(COPY),
    R(GLOB_DAT), R(JMP_SLOT), R(RELATIVE),
};
#undef R

static const struct {
    unsigned int machine;
    char *const *reloc_types;
    unsigned int nrtypes;
} reloc_tab[] = {
    { EM_386,    reloc_types_386,    ASIZE(reloc_types_386) },
    { EM_X86_64, reloc_types_X86_64, ASIZE(reloc_types_X86_64) },
    { EM_SPARC,  reloc_types_SPARC,  ASIZE(reloc_types_SPARC) },
    { EM_PPC,    reloc_types_PPC,    ASIZE(reloc_types_PPC) },
    { EM_68K,    reloc_types_68K,    ASIZE(reloc_types_68K) },
};

static char *const *reloc_types;
static unsigned int nrtypes;

static void print_file(const char *filename)
{
    void *buf;
    unsigned int i;
    Elf32_Ehdr *elf_header;
    unsigned char *ident;

    /* Read the file to memory */

    if (!(buf = load_file(filename)))
	return;

    elf_header = buf;

    ident = elf_header->e_ident;

    if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
	fprintf(stderr, "%s: No ELF file\n", filename);
	goto out;
    }
    if (ident[EI_CLASS] != ELFCLASS32 && ident[EI_CLASS] != ELFCLASS64) {
	fprintf(stderr, "%s: Unknown ELF class\n", filename);
	goto out;
    }
    if (ident[EI_CLASS] == ELFCLASS64) {
	fprintf(stderr, "%s: ELF64 not yet implemented\n", filename);
	goto out;
    }
    if (ident[EI_DATA] != ELFDATA2LSB && ident[EI_DATA] != ELFDATA2MSB) {
	fprintf(stderr, "%s: Unknown data encoding\n", filename);
	goto out;
    }
    if (ident[EI_VERSION] != EV_CURRENT) {
	fprintf(stderr, "%s: Unknown ELF version\n", filename);
	goto out;
    }

    conv(elf_header);

    set_relocation(elf_header->e_machine);

    /* and print it to stdout. */

    print_elf_header(elf_header);

    putchar('\n');
    print_program_header_table(elf_header);

    putchar('\n');
    print_section_header_table(elf_header);

    for (i = 0; i < elf_header->e_shnum; i++) {
	putchar('\n');
	print_section(elf_header, i);
    }

out:
    free(buf);
}

static void print_elf_header(const Elf32_Ehdr *e)
{
    printf("ELF Header\n"
	   "  Header Size: %u\n"
	   "  Type:        %s\n"
	   "  Machine:     %s\n"
	   "  Version:     %u\n"
	   "  Entry:       0x%08x\n"
	   "  Flags:       0x%x\n"
	   "  Sections:    %2u x %2u @ %08x\n"
	   "  Segments:    %2u x %2u @ %08x\n"
	   "  Shstrndx:    %u\n",
	   e->e_ehsize,
	   e->e_type    < NFTYPES ? elf_file_type[e->e_type]   : "?",
	   e->e_machine < NMTYPES ? machine_name[e->e_machine] : "?",
	   e->e_version, e->e_entry, e->e_flags,
	   e->e_shnum, e->e_shentsize, e->e_shoff,
	   e->e_phnum, e->e_phentsize, e->e_phoff,
	   e->e_shstrndx);
}

static Elf32_Phdr *program_header(const Elf32_Ehdr *e, unsigned int p)
{
    if (p >= e->e_phnum) {
	fprintf(stderr, "Illegal program header number %u\n", p);
	exit(1);
    }
    return (Elf32_Phdr *)((char *)e + e->e_phoff) + p;
}

static Elf32_Shdr *section_header(const Elf32_Ehdr *e, unsigned int s)
{
    if (s >= e->e_shnum) {
	fprintf(stderr, "Illegal section number %u\n", s);
	exit(1);
    }
    return (Elf32_Shdr *)((char *)e + e->e_shoff) + s;
}

static void *section_data(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    return (char *)e + sh->sh_offset;
}

static char *section_name(const Elf32_Ehdr *e, unsigned int s)
{
    char *strtab = section_data(e, section_header(e, e->e_shstrndx));
    return strtab + section_header(e, s)->sh_name;
}

static void print_program_header_table(const Elf32_Ehdr *e)
{
    unsigned int prg_header;

    printf("Program Header Table\n"
	   "    Type        Offset  Filesz  Vaddr     Paddr     Memsz   "
	   "Align   Flags\n");

    for (prg_header = 0; prg_header < e->e_phnum; prg_header++) {
	Elf32_Phdr *ph = program_header(e, prg_header);
	printf("    %-10s  %06x  %06x  %08x  %08x  %06x  %06x  %06x\n",
	       ph_type_name(ph->p_type),
	       ph->p_offset, ph->p_filesz,
	       ph->p_vaddr, ph->p_paddr, ph->p_memsz,
	       ph->p_align, ph->p_flags);
    }
}

static void print_section_header_table(const Elf32_Ehdr *e)
{
    unsigned int section;

    printf("Section Header Table\n"
	   " #  Type        "
	   "Offset  Size    Address  Link Info Align Flags Name\n");

    for (section = 0; section < e->e_shnum; section++) {
	const Elf32_Shdr *sh = section_header(e, section);
	printf("%2u  %-10s  %06x  %06x  %08x  %2u   %2u   %2u   %04x  %s\n",
	       section, section_type_name(sh->sh_type),
	       sh->sh_offset, sh->sh_size,
	       sh->sh_addr, sh->sh_link, sh->sh_info,
	       sh->sh_addralign, sh->sh_flags,
	       section_name(e, section)
	    );
    }
}

static void print_section(const Elf32_Ehdr *e, unsigned int section)
{
    const Elf32_Shdr *sh = section_header(e, section);

    if (section >= e->e_shnum)
	return;

    if (sh->sh_type == SHT_NOBITS)
	return;
    if (sh->sh_size == 0)
	return;

    printf("section: %u  %-10s %-10s %2u %2u 0x%08x %4u\n",
	   section, section_name(e, section), section_type_name(sh->sh_type),
	   sh->sh_link, sh->sh_info, sh->sh_addr, sh->sh_size);

    switch (sh->sh_type) {
    case SHT_STRTAB:
	print_strtab(e, sh);
	break;
    case SHT_SYMTAB:
    case SHT_DYNSYM:
	print_symtab(e, sh);
	break;
    case SHT_REL:
    case SHT_RELA:
	print_relocation(e, sh);
	break;
    case SHT_DYNAMIC:
	print_dynamic(e, sh);
	break;
    case SHT_HASH:
	break;
    default:
	print_other(e, sh);
	break;
    }
}

static void print_symtab(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    unsigned int      nsyms   = sh->sh_size / sh->sh_entsize;
    const Elf32_Sym  *symtab  = section_data(e, sh);
    const Elf32_Shdr *strtabh = section_header(e, sh->sh_link);
    const char       *strtab  = section_data(e, strtabh);
    const Elf32_Sym  *sym;

    for (sym = symtab; sym < symtab + nsyms; sym++) {
	printf("%4td: %-24s 0x%08x %4u %-6s %-7s %s\n",
	       sym - symtab,
	       strtab + sym->st_name,
	       sym->st_value, sym->st_size,
	       symbol_bind[ELF32_ST_BIND(sym->st_info)],
	       symbol_type[ELF32_ST_TYPE(sym->st_info)],
	       sym->st_shndx == SHN_UNDEF  ? "UNDEF" :
	       sym->st_shndx == SHN_ABS    ? "ABS" :
	       sym->st_shndx == SHN_COMMON ? "COMMON" :
	       section_name(e, sym->st_shndx)
	    );
    }
}

static void print_relocation(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    unsigned int      nrels   = sh->sh_size / sh->sh_entsize;
    const Elf32_Shdr *symtabh = section_header(e, sh->sh_link);
    const Elf32_Sym  *symtab  = section_data(e, symtabh);
    const Elf32_Shdr *strtabh = section_header(e, symtabh->sh_link);
    const char       *strtab  = section_data(e, strtabh);

    switch (sh->sh_type) {
    case SHT_REL: {
	const Elf32_Rel *rel, *reltab = section_data(e, sh);
	printf("Address   Type            Symbol\n");
	for (rel = reltab; rel < reltab + nrels; rel++) {
	    unsigned int sym  = ELF32_R_SYM(rel->r_info);
	    unsigned int type = ELF32_R_TYPE(rel->r_info);
	    printf("%08x  %-22s  %2u(%s)\n",
		   rel->r_offset, reloc_type_name(type), sym,
		   sym == STN_UNDEF ? "UNDEF" : strtab + symtab[sym].st_name
		);
	}
	break;
    }
    case SHT_RELA: {
	const Elf32_Rela *rel, *reltab = section_data(e, sh);
	printf("Address   Type            Addend    Symbol\n");
	for (rel = reltab; rel < reltab + nrels; rel++) {
	    unsigned int sym  = ELF32_R_SYM(rel->r_info);
	    unsigned int type = ELF32_R_TYPE(rel->r_info);
	    printf("%08x  %-22s  %08x  %2u(%s)\n",
		   rel->r_offset, reloc_type_name(type), rel->r_addend, sym,
		   sym == STN_UNDEF ? "UNDEF" : strtab + symtab[sym].st_name
		);
	}
	break;
    }
    }
}

static void print_strtab(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    unsigned int size = sh->sh_size;
    const char *s, *strtab = section_data(e, sh);

    for (s = strtab; s < strtab + size; s += strlen(s) + 1)
	printf("%4td: \"%s\"\n", s - strtab, s);
}

static void print_dynamic(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    unsigned int ndyns = sh->sh_size / sh->sh_entsize;
    const Elf32_Dyn *dyn, *dyntab = section_data(e, sh);
    Elf32_Addr symtab = 0, strtab = 0;

    for (dyn = dyntab; dyn < dyntab + ndyns; dyn++) {
	switch (dyn->d_tag) {
	case DT_SYMTAB:
	    symtab = dyn->d_un.d_ptr;
	    break;
	case DT_STRTAB:
	    strtab = dyn->d_un.d_ptr;
	    break;
	}
    }
    if (!symtab || !strtab) {
	fprintf(stderr,
		"No DT_SYMTAB or DT_STRTAB entry in DYNAMIC section\n");
	return;
    }
    for (dyn = dyntab; dyn < dyntab + ndyns; dyn++) {
	unsigned int tag = dyn->d_tag;
	char *tagname = tag < NTAGS ? tag_name[tag] : "?";
	switch (tag) {
	case DT_NEEDED:
	case DT_SONAME:
	case DT_RPATH:
	    printf("%-8s  %u (0x%08x)\n", tagname, dyn->d_un.d_val, strtab);
	    break;
	case DT_PLTRELSZ:
	case DT_RELASZ:
	case DT_RELAENT:
	case DT_RELSZ:
	case DT_RELENT:
	case DT_PLTREL:
	case DT_STRSZ:
	case DT_SYMENT:
	    printf("%-8s  %u\n", tagname, dyn->d_un.d_val);
	    break;
	case DT_INIT:
	case DT_FINI:
	case DT_PLTGOT:
	case DT_RELA:
	case DT_REL:
	case DT_HASH:
	case DT_SYMTAB:
	case DT_STRTAB:
	case DT_JMPREL:
	case DT_DEBUG:
	    printf("%-8s  %08x\n", tagname, dyn->d_un.d_ptr);
	    break;
	case DT_NULL:
	case DT_SYMBOLIC:
	case DT_TEXTREL:
	    puts(tagname);
	    break;
	default:
	    printf("%-8s  ?\n", tagname);
	    break;
	}
    }
}

static void print_other(const Elf32_Ehdr *e, const Elf32_Shdr *sh)
{
    dump(section_data(e, sh), sh->sh_size);
}

static char *ph_type_name(unsigned int type)
{
    static char s[16];

    if (type < NPTYPES)
	return program_header_type_names[type];
    else {
	sprintf(s, "0x%08x", type);
	return s;
    }
}

static char *section_type_name(unsigned int type)
{
    static char s[16];

    if (type < NSTYPES)
	return section_type_names[type];
    else {
	sprintf(s, "0x%08x", type);
	return s;
    }
}

static char *reloc_type_name(unsigned int type)
{
    static char s[16];

    if (type < nrtypes)
	return reloc_types[type];
    else {
	sprintf(s, "%u", type);
	return s;
    }
}

static void set_relocation(unsigned int machine)
{
    unsigned int i;

    reloc_types = NULL;
    nrtypes     = 0;
    for (i = 0; i < ASIZE(reloc_tab); i++)
	if (machine == reloc_tab[i].machine) {
	    reloc_types = reloc_tab[i].reloc_types;
	    nrtypes     = reloc_tab[i].nrtypes;
	    break;
	}
}

static char *load_file(const char *filename)
{
    char *buf;
    int fd;
    struct stat statbuf;
    size_t size;

    if ((fd = open(filename, O_RDONLY)) < 0) {
	perror(filename);
	return NULL;
    }
    if (fstat(fd, &statbuf) < 0) {
	perror(filename);
	close(fd);
	return NULL;
    }

    size = statbuf.st_size;
    if (!(buf = malloc(size))) {
	fprintf(stderr, "%s: Insufficient memory.\n", filename);
	close(fd);
	return NULL;
    }
    if (read(fd, buf, size) < 0) {
	perror(filename);
	free(buf);
	close(fd);
	return NULL;
    }
    close(fd);

    return buf;
}

#define BYTES_PER_LINE 16

static void dump(const void *s, size_t size)
{
    const unsigned char *p, *start = s;
    int nbytes, i;

    for (p = start; size > 0; p += nbytes, size -= nbytes) {
	nbytes = min(size, BYTES_PER_LINE);

	printf("%06tx ", p - start);
	for (i = 0; i < nbytes; i++)
	    printf(" %02x", p[i]);
	for (i = nbytes; i < BYTES_PER_LINE; i++)
	    fputs("   ", stdout);
	fputs("   ", stdout);
	for (i = 0; i < nbytes; i++)
	    putchar(isprint(p[i]) ? p[i] : '.');
	putchar('\n');
    }
}

static size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

/* Routines for MSB/LSB conversion */

static unsigned char host_endianness(void)
{
    static const union { Elf32_Word w; char c[4]; } w = { .w = 0x01020304 };
    static const union { Elf32_Half h; char c[2]; } h = { .h = 0x0102 };

    if (w.c[0] == 1 && w.c[1] == 2 && w.c[2] == 3 && w.c[3] == 4
	&& h.c[0] == 1 && h.c[1] == 2)
	return ELFDATA2MSB;
    else if (w.c[0] == 4 && w.c[1] == 3 && w.c[2] == 2 && w.c[3] == 1
	     && h.c[0] == 2 && h.c[1] == 1)
	return ELFDATA2LSB;
    else
	return ELFDATANONE;
}

static void swap_s(unsigned short *p)
{
    unsigned char c, *cp = (unsigned char *)p;
    c = cp[0], cp[0] = cp[1], cp[1] = c;
}

static void swap_l(unsigned int *p)
{
    unsigned char c, *cp = (unsigned char *)p;
    c = cp[0], cp[0] = cp[3], cp[3] = c;
    c = cp[1], cp[1] = cp[2], cp[2] = c;
}

static void nop_s(unsigned short *p)
{
}

static void nop_l(unsigned int *p)
{
}

static void (*conv_s)(unsigned short *), (*conv_l)(unsigned int *);

static void conv(Elf32_Ehdr *e)
{
    int elf_endianness = e->e_ident[EI_DATA];
    unsigned int i;

    if (host_endianness() == elf_endianness) {
	conv_s = nop_s;
	conv_l = nop_l;
    } else {
	conv_s = swap_s;
	conv_l = swap_l;
    }

    conv_elfheader(e);

    for (i = 0; i < e->e_shnum; i++)
	conv_sectionheader(e, section_header(e, i));

    for (i = 0; i < e->e_phnum; i++)
	conv_programheader(e, program_header(e, i));
}

static void conv_elfheader(Elf32_Ehdr *e)
{
    conv_s(&e->e_type);
    conv_s(&e->e_machine);
    conv_l(&e->e_version);
    conv_l(&e->e_entry);
    conv_l(&e->e_phoff);
    conv_l(&e->e_shoff);
    conv_l(&e->e_flags);
    conv_s(&e->e_ehsize);
    conv_s(&e->e_phentsize);
    conv_s(&e->e_phnum);
    conv_s(&e->e_shentsize);
    conv_s(&e->e_shnum);
    conv_s(&e->e_shstrndx);
}

static void conv_programheader(Elf32_Ehdr *e, Elf32_Phdr *ph)
{
    conv_l(&ph->p_type);
    conv_l(&ph->p_offset);
    conv_l(&ph->p_vaddr);
    conv_l(&ph->p_paddr);
    conv_l(&ph->p_filesz);
    conv_l(&ph->p_memsz);
    conv_l(&ph->p_flags);
    conv_l(&ph->p_align);
}

static void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *sh)
{
    conv_l(&sh->sh_name);
    conv_l(&sh->sh_type);
    conv_l(&sh->sh_flags);
    conv_l(&sh->sh_addr);
    conv_l(&sh->sh_offset);
    conv_l(&sh->sh_size);
    conv_l(&sh->sh_link);
    conv_l(&sh->sh_info);
    conv_l(&sh->sh_addralign);
    conv_l(&sh->sh_entsize);

    switch (sh->sh_type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
	conv_symboltable(e, sh);
	break;
    case SHT_REL:
    case SHT_RELA:
	conv_relocation(e, sh);
	break;
    case SHT_DYNAMIC:
	conv_dynamic(e, sh);
	break;
    }
}

static void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *sh)
{
    Elf32_Sym *p, *symtab = section_data(e, sh);
    unsigned int nsyms = sh->sh_size / sh->sh_entsize;

    for (p = symtab; p < symtab + nsyms; p++) {
	conv_l(&p->st_name);
	conv_l(&p->st_value);
	conv_l(&p->st_size);
	conv_s(&p->st_shndx);
    }
}

static void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *sh)
{
    unsigned int nrels = sh->sh_size / sh->sh_entsize;

    switch (sh->sh_type) {
    case SHT_REL: {
	Elf32_Rel *p, *rel = section_data(e, sh);
	for (p = rel; p < rel + nrels; p++) {
	    conv_l(&p->r_offset);
	    conv_l(&p->r_info);
	}
	break;
    }
    case SHT_RELA: {
	Elf32_Rela *p, *rel = section_data(e, sh);
	for (p = rel; p < rel + nrels; p++) {
	    conv_l(&p->r_offset);
	    conv_l(&p->r_info);
	    conv_l(&p->r_addend);
	}
	break;
    }
    }
}

static void conv_dynamic(Elf32_Ehdr *e, Elf32_Shdr *sh)
{
    unsigned int ndyn = sh->sh_size / sh->sh_entsize;
    Elf32_Dyn *dyn, *dyntab = section_data(e, sh);

    for (dyn = dyntab; dyn < dyntab + ndyn; dyn++) {
	conv_l(&dyn->d_tag);
	conv_l(&dyn->d_un.d_val);
    }
}
