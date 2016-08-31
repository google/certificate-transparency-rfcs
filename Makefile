DOC = draft-ietf-trans-rfc6962-bis

# Not much user servicable parts below this line.

VER=$(shell grep ^docname: $(DOC).md | awk -F- '{print $$NF}')
TEXT=$(DOC)-$(VER).txt
HTML=$(DOC)-$(VER).html
XML=$(DOC).xml

all: $(TEXT) $(HTML) 

$(XML): $(DOC).md
	XML_RESOURCE_ORG_PREFIX="https://xml2rfc.tools.ietf.org/public/rfc" kramdown-rfc2629 $< > $@

$(TEXT): $(XML)
	xml2rfc $<

$(HTML): $(DOC).xml
	xml2rfc $< --html

clean:
	rm -f $(DOC).html $(DOC).txt $(DOC).xml
