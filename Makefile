#
# $Id: Makefile,v 1.1 2012/04/28 05:21:03 urs Exp $
#

RM      = rm -f
CFLAGS  = -Os
LDFLAGS = -s

programs = printelf

.PHONY: all
all: $(programs)

.PHONY: clean
clean:
	$(RM) $(programs) *.o core
