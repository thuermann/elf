#
# $Id: Makefile,v 1.2 2014/02/08 17:06:36 urs Exp $
#

RM      = rm -f
CFLAGS  = -Os -Wall -Wextra
LDFLAGS = -s

programs = printelf

.PHONY: all
all: $(programs)

.PHONY: clean
clean:
	$(RM) $(programs) *.o core
