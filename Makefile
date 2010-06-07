include $(GOROOT)/src/Make.$(GOARCH)

TARG = http-gonsole
GOFILES= http-gonsole.go

include $(GOROOT)/src/Make.cmd
