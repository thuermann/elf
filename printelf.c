/*
 * $Id: printelf.c,v 1.5 2000/11/02 20:14:30 urs Exp $
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

/* MSB/LSB conversion routines */

void conv(Elf32_Ehdr *e);
void conv_elfheader(Elf32_Ehdr *e);
void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *shp);
void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *shp);
void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp);

#define section_header(e,s) ((Elf32_Shdr*)((char*)(e) + (e)->e_shoff) + (s))

#define section_name(e,s) \
	((char*)(e) + section_header(e, e->e_shstrndx)->sh_offset \
		    + section_header(e,s)->sh_name)

char *section_type_name[] = {
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

char *elf_file_type[] = {
    "NONE",
    "REL",
    "EXEC",
    "DYN",
    "CORE",
};

char *machine_name[] = {
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


void usage(char *name)
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

print_file(char *filename)
{
    int fd;
    struct stat statbuf;
    void *buf;
    int size;
    int i;
    Elf32_Ehdr *elf_header;

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

    elf_header = buf;

    conv(elf_header);

    printf("ELF type: %s, version: %d, machine: %s, "
	   "#sections: %d, #segments: %d\n\n",
	   elf_file_type[elf_header->e_type],
	   elf_header->e_version,
	   machine_name[elf_header->e_machine],
	   elf_header->e_shnum, elf_header->e_phnum);

    print_section_header_table(elf_header);
    putchar('\n');
    for (i = 0; i < elf_header->e_shnum; i++) {
	dump_section(elf_header, i);
	putchar('\n');
    }

    free(buf);
}

print_section_header_table(Elf32_Ehdr *e)
{
    int section;

    printf(" # Name       Type     Link Info Address    Offset Size Align\n");

    for (section = 0; section < e->e_shnum; section++) {
	Elf32_Shdr *shp = section_header(e, section);
	printf("%2d %-10s %-8s  %2d   %2d  0x%08x  %05x %4d %2d\n",
	       section, section_name(e, section),
	       section_type_name[shp->sh_type],
	       shp->sh_link, shp->sh_info,
	       shp->sh_addr,
	       shp->sh_offset, shp->sh_size,
	       shp->sh_addralign);
    }
}

#define BYTES_PER_LINE 16

dump_section(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);

    if (section >= e->e_shnum)
	return;

    if (shp->sh_type == SHT_NOBITS)
	return;
    if (shp->sh_size == 0)
	return;

    printf("section: %d  %-10s %-8s %2d %2d 0x%08x %4d\n",
	   section, section_name(e, section),
	   section_type_name[shp->sh_type],
	   shp->sh_link, shp->sh_info,
	   shp->sh_addr, shp->sh_size);

    switch (shp->sh_type) {
    case SHT_STRTAB:
	dump_strtab(e, section);
	break;
    case SHT_SYMTAB:
	dump_symtab(e, section);
	break;
    case SHT_REL:
    case SHT_RELA:
	dump_relocation(e, section);
	break;
    default:
	dump_other(e, section);
	break;
    }
}

char *bind[] = {
    "LOCAL",
    "GLOBAL",
    "WEAK",
};

char *symbol_type[] = {
    "NOTYPE",
    "OBJECT",
    "FUNC",
    "SECTION",
    "FILE",
};

dump_symtab(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);
    Elf32_Sym *p, *symtab = (Elf32_Sym*)((char*)e + shp->sh_offset);
    int link = shp->sh_link;
    char *strtab = (char*)e + section_header(e, shp->sh_link)->sh_offset;
    int nsyms = shp->sh_size / shp->sh_entsize;

    for (p = symtab; p < symtab + nsyms; p++) {
	printf("%4d: %-20s 0x%08x %4d %-6s %-7s %-10s\n",
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

dump_relocation(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);
    Elf32_Rel *p, *rel = (Elf32_Rel*)((char*)e + shp->sh_offset);
    Elf32_Shdr *symtabh = section_header(e, shp->sh_link);
    Elf32_Sym *symtab = (Elf32_Sym*)((char*)e + symtabh->sh_offset);
    char *strtab = (char*)e + section_header(e, symtabh->sh_link)->sh_offset;
    int nrels = shp->sh_size / shp->sh_entsize;

    for (p = rel; p < rel + nrels; p++) {
	int sym = ELF32_R_SYM(p->r_info);
	printf("  0x%08x %2d %2d(%s)\n",
	       p->r_offset,
	       ELF32_R_TYPE(p->r_info),
	       sym,
	       sym == STN_UNDEF ? "UNDEF" : strtab + symtab[sym].st_name
	    );
    }
}

dump_strtab(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);
    char *p, *start = (char*)e + shp->sh_offset;
    int size = shp->sh_size;

    for (p = start; p < start + size; p += strlen(p) + 1)
	printf("%4d: \"%s\"\n", p - start, p);
}

dump_other(Elf32_Ehdr *e, int section)
{
    Elf32_Shdr *shp = section_header(e, section);
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

void swap4(unsigned char *p)
{
    unsigned char c;
    c = p[0], p[0] = p[3], p[3] = c;
    c = p[1], p[1] = p[2], p[2] = c;
}

void swap2(unsigned char *p)
{
    unsigned char c;
    c = p[0], p[0] = p[1], p[1] = c;
}

void lsbtoh(unsigned int *p)
{
}

void msbtoh(unsigned int *p)
{
    swap4((unsigned char *)p);
}

void lsbtohs(unsigned short *p)
{
}

void msbtohs(unsigned short *p)
{
    swap2((unsigned char *)p);
}

void (*conv_s)(unsigned short *), (*conv_l)(unsigned int *);

void conv(Elf32_Ehdr *e)
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

void conv_elfheader(Elf32_Ehdr *e)
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

void conv_sectionheader(Elf32_Ehdr *e, Elf32_Shdr *shp)
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

void conv_symboltable(Elf32_Ehdr *e, Elf32_Shdr *shp)
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

void conv_relocation(Elf32_Ehdr *e, Elf32_Shdr *shp)
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
