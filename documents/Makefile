#######################################

FILES += draft-tschudin-icnrg-flic-02
FILES += draft-wood-icnrg-clean-00
FILES += draft-wood-icnrg-esic-00
FILES += draft-wood-icnrg-ccnxkeyexchange-02

FILES += draft-irtf-icnrg-ccnxmessages-04
FILES += draft-irtf-icnrg-ccnxsemantics-04
FILES += draft-mosko-icnrg-ccnxuri-03

FILES += draft-mosko-icnrg-ccnxchunking-02
FILES += draft-mosko-icnrg-cachecontrol-00
FILES += draft-mosko-icnrg-beginendfragment-03

#FILES += draft-mosko-icnrg-ccnxfragmentation-01
#FILES += draft-mosko-icnrg-selectors-01

#######################################

TXT =  $(foreach x, $(FILES), $(x).txt)
HTML = $(foreach x, $(FILES), $(x).html)

#######################################

.PHONY: clean format

all: format
	mv *.txt build
	mv *.html build

format: $(TXT) $(HTML)

%.txt: %.xml
	xml2rfc $<

%.html: %.xml
	xml2rfc --html $<

%.xml: %.md
	kramdown-rfc2629 $< >$@

clean:
	rm -f %.xml *~

#######################################

#all: ${FN}.txt ${FN}.html
#
#${FN}.txt: ${FN}.xml
#	xml2rfc $<
#
#${FN}.html: ${FN}.xml
#	xml2rfc --html $<
#
#${FN}.xml: ${FN}.mkd
#	kramdown-rfc2629 $< >$@
#
#clean:
#	rm -f ${FN}.xml *~
