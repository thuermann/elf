/*
 * $Id: printelf.c,v 1.18 2005/10/27 11:47:49 urs Exp $
 *
 * Read an ELF file and print it to stdout.
 *
 * Currently, this works only, if the ELF file has the same endianness
 * as the machine this program runs on.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <elf.h>

static void print_file(char *filename);
static void print_elf_header(Elf32_Ehdr *e);
static void print_program_header_table(Elf32_Ehdr *e);
static void print_section_header_table(Elf32_Ehdr *e);

static void dump_section(Elf32_Ehdr *e, int section);
static void dump_symtab(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void dump_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void dump_strtab(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void dump_dynamic(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void dump_other(Elf32_Ehdr *e, Elf32_Shdr *shp);

static char *section_type_name(unsigned int type);

static Elf32_Off addr2offset(Elf32_Addr addr);

/* MSB/LSB conversion routines */

static void conv(Elf32_Ehdr *e);
static void conv_elfheader(Elf32_Ehdr *e);
static void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *shp);
static void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp);



#define ASIZE(a) (sizeof(a)/sizeof(*a))

static char *const section_type_names[] = {
    "NULL",
    "PROGBITS",
    "SYMTAB",
    "STRTAB",
    "RELA",
    "HASH",
    "DYNAMIC",
    "NOTE",
    "NOBITS",
    "REL",
    "SHLIB",
    "DYNSYM",
    "NUM",
};
#define NSTYPES ASIZE(section_type_names)

static char *const program_header_type_names[] = {
    "NULL",
    "LOAD",
    "DYNAMIC",
    "INTERP",
    "NOTE",
    "SHLIB",
    "PHDR",
};
#define NPTYPES ASIZE(program_header_type_names)

static char *const elf_file_type[] = {
    "NONE",
    "REL",
    "EXEC",
    "DYN",
    "CORE",
};
#define NFTYPES ASIZE(elf_file_type)

static char *const machine_name[] = {
    "NONE",         /*   0  No machine */
    "M32",          /*   1  AT&T WE 32100 */
    "SPARC",        /*   2  SUN SPARC */
    "386",          /*   3  Intel 80386 */
    "68K",          /*   4  Motorola m68k family */
    "88K",          /*   5  Motorola m88k family */
    "486",          /*   6  Intel 80486 */
    "860",          /*   7  Intel 80860 */
    "MIPS",         /*   8  MIPS R3000 big-endian */
    "S370",         /*   9  Amdahl */
    "MIPS_RS4_BE",  /*  10  MIPS R4000 big-endian */
    "RS6000",       /*  11  RS6000 */

    0,0,0,

    "PARISC",       /*  15  HPPA */
    "nCUBE",        /*  16  nCUBE */
    "VPP500",       /*  17  Fujitsu VPP500 */
    "SPARC32PLUS",  /*  18  Sun's "v8plus" */
    "960",          /*  19  Intel 80960 */
    "PPC",          /*  20  PowerPC */

    0,0,0,0,0,  0,0,0,0,0,  0,0,0,0,0,

    "V800",         /*  36  NEC V800 series */
    "FR20",         /*  37  Fujitsu FR20 */
    "RH32",         /*  38  TRW RH32 */
    "MMA",          /*  39  Fujitsu MMA */
    "ARM",          /*  40  ARM */
    "FAKE_ALPHA",   /*  41  Digital Alpha */
    "SH",           /*  42  Hitachi SH */
    "SPARCV9",      /*  43  SPARC v9 64-bit */
    "TRICORE",      /*  44  Siemens Tricore */
    "ARC",          /*  45  Argonaut RISC Core */
    "H8_300",       /*  46  Hitachi H8/300 */
    "H8_300H",      /*  47  Hitachi H8/300H */
    "H8S",          /*  48  Hitachi H8S */
    "H8_500",       /*  49  Hitachi H8/500 */
    "IA_64",        /*  50  Intel Merced */
    "MIPS_X",       /*  51  Stanford MIPS-X */
    "COLDFIRE",     /*  52  Motorola Coldfire */
    "68HC12",       /*  53  Motorola M68HC12 */
};
#define NMTYPES ASIZE(machine_name)

static char *const reloc_types_386[] = {
    "386_NONE",
    "386_32",
    "386_PC32",
    "386_GOT32",
    "386_PLT32",
    "386_COPY",
    "386_GLOB_DAT",
    "386_JMP_SLOT",
    "386_RELATIVE",
    "386_GOTOFF",
    "386_GOTPC",
};

static char *const reloc_types_SPARC[] = {
    "?",
    "?",
    "?",
    "?",
    "?",
    "?",
    "?",
    "SPARC_WDISP30",
    "?",
    "SPARC_HI22",
    "?",
    "?",
    "SPARC_LO10",
};

static char *const *reloc_type;
static int  nrtypes;

static char *const tag_name[] = {
    "NULL",
    "NEEDED",
    "PLTRELSZ",
    "PLTGOT",
    "HASH",
    "STRTAB",
    "SYMTAB",
    "RELA",
    "RELASZ",
    "RELAENT",
    "STRSZ",
    "SYMENT",
    "INIT",
    "FINI",
    "SONAME",
    "RPATH",
    "SYMBOLIC",
    "REL",
    "RELSZ",
    "RELENT",
    "PLTREL",
    "DEBUG",
    "TEXTREL",
    "JMPREL",
};
#define NTAGS ASIZE(tag_name)



static void usage(char *name)
{
    fprintf(stderr, "Usage: %s [-hv] file...\n", name);
}

int main(int argc, char **argv)
{
    int c;

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

static void print_file(char *filename)
{
    int fd;
    struct stat statbuf;
    void *buf;
    int size;
    int i;
    Elf32_Ehdr *elf_header;

    /* Read the file to memory */

    if ((fd = open(filename, O_RDONLY)) < 0) {
	perror(filename);
	return;
    }
    if (fstat(fd, &statbuf) < 0) {
	perror(filename);
	close(fd);
	return;
    }

    size = statbuf.st_size;
    if (!(buf = malloc(size))) {
	fprintf(stderr, "%s: Insufficient memory.\n", filename);
	close(fd);
	return;
    }
    if (read(fd, buf, size) < 0) {
	perror(filename);
	free(buf);
	close(fd);
	return;
    }
    close(fd);

    /* and print dump it stdout. */

    elf_header = buf;

    conv(elf_header);

    switch (elf_header->e_machine) {
    case EM_386:
	reloc_type = reloc_types_386;
	nrtypes    = ASIZE(reloc_types_386);
	break;
    case EM_SPARC:
	reloc_type = reloc_types_SPARC;
	nrtypes    = ASIZE(reloc_types_SPARC);
	break;
    default:
	reloc_type = NULL;
	nrtypes    = 0;
	break;
    }

    print_elf_header(elf_header);

    print_program_header_table(elf_header);
    putchar('\n');

    print_section_header_table(elf_header);
    putchar('\n');
    for (i = 0; i < elf_header->e_shnum; i++) {
	dump_section(elf_header, i);
	putchar('\n');
    }

    free(buf);
}

static void print_elf_header(Elf32_Ehdr *e)
{
    printf("ELF Header\n"
	   "  Header Size: %d\n"
	   "  Type:        %s\n"
	   "  Machine:     %s\n"
	   "  Version:     %d\n"
	   "  Entry:       0x%08x\n"
	   "  Flags:       0x%x\n"
	   "  Sections:    %2d x %2d @ %08x\n"
	   "  Segments:    %2d x %2d @ %08x\n"
	   "  Shstrndx:    %d\n\n",
	   e->e_ehsize,
	   e->e_type    < NFTYPES ? elf_file_type[e->e_type]   : "?",
	   e->e_machine < NMTYPES ? machine_name[e->e_machine] : "?",
	   e->e_version, e->e_entry, e->e_flags,
	   e->e_shnum, e->e_shentsize, e->e_shoff,
	   e->e_phnum, e->e_phentsize, e->e_phoff,
	   e->e_shstrndx);
}

static Elf32_Shdr *section_header(Elf32_Ehdr *e, int s)
{
    if (s >= e->e_shnum) {
	fprintf(stderr, "Illegal section number %d\n", s);
	exit(1);
    }
    return (Elf32_Shdr*)((char*)e + e->e_shoff) + s;
}

static char *section_name(Elf32_Ehdr *e, int s)
{
    return (char*)e + section_header(e, e->e_shstrndx)->sh_offset
	+ section_header(e, s)->sh_name;
}

static Elf32_Phdr *program_header(Elf32_Ehdr *e, int p)
{
    if (p >= e->e_phnum) {
	fprintf(stderr, "Illegal program header number %d\n", p);
	exit(1);
    }
    return (Elf32_Phdr*)((char*)e + e->e_phoff) + p;
}

static void print_section_header_table(Elf32_Ehdr *e)
{
    int section;

    printf("Section Header Table\n"
	   " #  Type      "
	   "Offset  Size    Address  Link Info Align Flags Name\n");

    for (section = 0; section < e->e_shnum; section++) {
	Elf32_Shdr *shp = section_header(e, section);
	printf("%2d  %-8s  %06x  %06x  %08x  %2d   %2d   %2d   %04x  %-16s\n",
	       section, section_type_name(shp->sh_type),
	       shp->sh_offset, shp->sh_size,
	       shp->sh_addr, shp->sh_link, shp->sh_info,
	       shp->sh_addralign, shp->sh_flags,
	       section_name(e, section)
	    );
    }
}

#define BYTES_PER_LINE 16

static void dump_section(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);

    if (section >= e->e_shnum)
	return;

    if (shp->sh_type == SHT_NOBITS)
	return;
    if (shp->sh_size == 0)
	return;

    printf("section: %d  %-10s %-10s %2d %2d 0x%08x %4d\n",
	   section, section_name(e, section), section_type_name(shp->sh_type),
	   shp->sh_link, shp->sh_info, shp->sh_addr, shp->sh_size);

    switch (shp->sh_type) {
    case SHT_STRTAB:
	dump_strtab(e, shp);
	break;
    case SHT_SYMTAB:
    case SHT_DYNSYM:
	dump_symtab(e, shp);
	break;
    case SHT_REL:
    case SHT_RELA:
	dump_relocation(e, shp);
	break;
    case SHT_DYNAMIC:
	dump_dynamic(e, shp);
	break;
    case SHT_HASH:
	break;
    default:
	dump_other(e, shp);
	break;
    }
}

static char *const bind[] = {
    "LOCAL",
    "GLOBAL",
    "WEAK",
};

static char *const symbol_type[] = {
    "NOTYPE",
    "OBJECT",
    "FUNC",
    "SECTION",
    "FILE",
};

static void dump_symtab(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    Elf32_Sym *p, *symtab = (Elf32_Sym*)((char*)e + shp->sh_offset);
    int link = shp->sh_link;
    char *strtab = (char*)e + section_header(e, shp->sh_link)->sh_offset;
    int nsyms = shp->sh_size / shp->sh_entsize;

    for (p = symtab; p < symtab + nsyms; p++) {
	printf("%4d: %-24s 0x%08x %4d %-6s %-7s %-10s\n",
	       p - symtab,
	       strtab + p->st_name,
	       p->st_value, p->st_size,
	       bind[ELF32_ST_BIND(p->st_info)],
	       symbol_type[ELF32_ST_TYPE(p->st_info)],
	       p->st_shndx == SHN_UNDEF ? "UNDEF" :
	       (p->st_shndx == SHN_ABS ? "ABS" :
		(p->st_shndx == SHN_COMMON ? "COMMON" :
		 section_name(e, p->st_shndx)))
	    );
    }
}

static void dump_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    Elf32_Shdr *symtabh = section_header(e, shp->sh_link);
    Elf32_Sym *symtab = (Elf32_Sym*)((char*)e + symtabh->sh_offset);
    char *strtab = (char*)e + section_header(e, symtabh->sh_link)->sh_offset;
    int nrels = shp->sh_size / shp->sh_entsize;
    int type = shp->sh_type;

    switch (shp->sh_type) {
    case SHT_REL: {
	Elf32_Rel *p, *rel = (Elf32_Rel*)((char*)e + shp->sh_offset);
	printf("Address   Type            Symbol\n");
	for (p = rel; p < rel + nrels; p++) {
	    int sym  = ELF32_R_SYM(p->r_info);
	    int type = ELF32_R_TYPE(p->r_info);
	    printf("%08x  %-14s  %2d(%s)\n",
		   p->r_offset,
		   type < nrtypes ? reloc_type[type] : "?",
		   sym,
		   sym == STN_UNDEF ? "UNDEF" : strtab + symtab[sym].st_name
		);
	}
    }
    break;
    case SHT_RELA: {
	Elf32_Rela *p, *rel = (Elf32_Rela*)((char*)e + shp->sh_offset);
	printf("Address   Type            Addend    Symbol\n");
	for (p = rel; p < rel + nrels; p++) {
	    int sym  = ELF32_R_SYM(p->r_info);
	    int type = ELF32_R_TYPE(p->r_info);
	    printf("%08x  %-14s  %08x  %2d(%s)\n",
		   p->r_offset,
		   type < nrtypes ? reloc_type[type] : "?",
		   p->r_addend,
		   sym,
		   sym == STN_UNDEF ? "UNDEF" : strtab + symtab[sym].st_name
		);
	}
    }
    break;
    }
}

static void dump_strtab(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    char *p, *start = (char*)e + shp->sh_offset;
    int size = shp->sh_size;

    for (p = start; p < start + size; p += strlen(p) + 1)
	printf("%4d: \"%s\"\n", p - start, p);
}

static void dump_dynamic(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    Elf32_Dyn *p, *dyn = (Elf32_Dyn*)((char*)e + shp->sh_offset);
    int ndyns = shp->sh_size / shp->sh_entsize;
    char *strtab      = NULL;
    Elf32_Sym *symtab = NULL;

    for (p = dyn; p < dyn + ndyns; p++) {
	switch (p->d_tag) {
	case DT_SYMTAB:
	    symtab = (Elf32_Sym*)((char*)e + addr2offset(p->d_un.d_ptr));
	    break;
	case DT_STRTAB:
	    strtab = (char*)e + addr2offset(p->d_un.d_ptr);
	    break;
	}
    }
    if (!symtab || !strtab) {
	fprintf(stderr,
		"No DT_SYMTAB or DT_STRTAB entry in DYNAMIC section\n");
	return;
    }
    for (p = dyn; p < dyn + ndyns; p++) {
	int tag = p->d_tag;
	char *tagname = tag < NTAGS ? tag_name[tag] : "?";
	switch (tag) {
	case DT_NEEDED:
	case DT_SONAME:
	case DT_RPATH:
	    printf("%-8s  %d (0x%08x)\n", tagname, p->d_un.d_val, strtab);
	    break;
	case DT_PLTRELSZ:
	case DT_RELASZ:
	case DT_RELAENT:
	case DT_STRSZ:
	case DT_SYMENT:
	    printf("%-8s  %d\n", tagname, p->d_un.d_val);
	    break;
	case DT_PLTGOT:
	case DT_RELA:
	case DT_HASH:
	case DT_SYMTAB:
	case DT_STRTAB:
	case DT_JMPREL:
	case DT_DEBUG:
	    printf("%-8s  %08x\n", tagname, p->d_un.d_ptr);
	    break;
	default:
	    printf("%-8s  ?\n", tagname);
	    break;
	}
    }
}

static void dump_other(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    unsigned char *p, *start = (unsigned char*)e + shp->sh_offset;
    int size = shp->sh_size;
    int nbytes, i;

    for (p = start; size > 0; p += BYTES_PER_LINE) {
	printf("%06x ", p - start);
	nbytes = size > BYTES_PER_LINE ? BYTES_PER_LINE : size;
	size -= nbytes;
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

static void print_program_header_table(Elf32_Ehdr *e)
{
    int prg_header;

    printf("Program Header Table\n"
	   "    Type      Offset  Filesz  Vaddr     Paddr     Memsz   "
	   "Align   Flags\n");

    for (prg_header = 0; prg_header < e->e_phnum; prg_header++) {
	Elf32_Phdr *php = program_header(e, prg_header);
	printf("    %-8s  %06x  %06x  %08x  %08x  %06x  %06x  %06x\n",
	       ph_type_name(php->p_type),
	       php->p_offset, php->p_filesz,
	       php->p_vaddr, php->p_paddr, php->p_memsz,
	       php->p_align, php->p_flags);
    }
}


static Elf32_Off addr2offset(Elf32_Addr addr)
{
    return addr;
}

static void swap4(unsigned char *p)
{
    unsigned char c;
    c = p[0], p[0] = p[3], p[3] = c;
    c = p[1], p[1] = p[2], p[2] = c;
}

static void swap2(unsigned char *p)
{
    unsigned char c;
    c = p[0], p[0] = p[1], p[1] = c;
}

static void lsbtoh(unsigned int *p)
{
}

static void msbtoh(unsigned int *p)
{
    swap4((unsigned char *)p);
}

static void lsbtohs(unsigned short *p)
{
}

static void msbtohs(unsigned short *p)
{
    swap2((unsigned char *)p);
}

static void (*conv_s)(unsigned short *), (*conv_l)(unsigned int *);

static void conv(Elf32_Ehdr *e)
{
    int i;

    if (e->e_ident[EI_DATA] == ELFDATA2LSB) {
	conv_s = lsbtohs;
	conv_l = lsbtoh;
    } else if (e->e_ident[EI_DATA] == ELFDATA2MSB) {
	conv_s = msbtohs;
	conv_l = msbtoh;
    }
    conv_elfheader(e);

    for (i = 0; i < e->e_shnum; i++)
	conv_sectionheader(e, section_header(e, i));
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

static void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    conv_l(&shp->sh_name);
    conv_l(&shp->sh_type);
    conv_l(&shp->sh_flags);
    conv_l(&shp->sh_addr);
    conv_l(&shp->sh_offset);
    conv_l(&shp->sh_size);
    conv_l(&shp->sh_link);
    conv_l(&shp->sh_info);
    conv_l(&shp->sh_addralign);
    conv_l(&shp->sh_entsize);

    switch (shp->sh_type) {
    case SHT_SYMTAB:
	conv_symboltable(e, shp);
	break;
    case SHT_REL:
    case SHT_RELA:
	conv_relocation(e, shp);
	break;
    }
}

static void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    Elf32_Sym *p, *symtab = (Elf32_Sym*)((char*)e + shp->sh_offset);
    int nsyms = shp->sh_size / shp->sh_entsize;

    for (p = symtab; p < symtab + nsyms; p++) {
	conv_l(&p->st_name);
	conv_l(&p->st_value);
	conv_l(&p->st_size);
	conv_s(&p->st_shndx);
    }
}

static void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp)
{
    int nrels = shp->sh_size / shp->sh_entsize;

    switch (shp->sh_type) {
    case SHT_REL: {
	Elf32_Rel *p, *rel = (Elf32_Rel*)((char*)e + shp->sh_offset);
	for (p = rel; p < rel + nrels; p++) {
	    conv_l(&p->r_offset);
	    conv_l(&p->r_info);
	}
    }
    break;
    case SHT_RELA: {
	Elf32_Rela *p, *rel = (Elf32_Rela*)((char*)e + shp->sh_offset);
	for (p = rel; p < rel + nrels; p++) {
	    conv_l(&p->r_offset);
	    conv_l(&p->r_info);
	    conv_l(&p->r_addend);
	}
    }
    break;
    }
}
